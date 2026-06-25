//! Native libkrun display/input bridge for Local Machines.
//!
//! The VM owns the framebuffer callbacks. A bounded worker publishes those
//! frames through a password-protected RFB server bound only to loopback, while
//! a mode-0600 Unix rendezvous socket returns the per-launch endpoint.

use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError};
use krun_display::{
    DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayBackendNew, IntoDisplayBackend,
    Rect, ResourceFormat,
};
use krun_input::{
    InputAbsInfo, InputBackendError, InputDeviceIds, InputEvent, InputEventType, InputEventsImpl,
    InputQueryConfig, IntoInputConfig, IntoInputEvents, ObjectNew,
};
use krun_utils::pollable_channel::{
    pollable_channel, PollableChannelReciever, PollableChannelSender,
};
use rand::{distributions::Alphanumeric, Rng};
use rustvncserver::{server::ServerEvent, VncServer};
use serde::{Deserialize, Serialize};
use std::array;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::Read;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::mpsc;

/// Default native scanout width.
pub const DISPLAY_WIDTH: u32 = 1_440;
/// Default native scanout height.
pub const DISPLAY_HEIGHT: u32 = 900;
const DISPLAY_BUFFERS: usize = 3;
const FRAME_QUEUE_DEPTH: usize = 2;
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

const EV_SYN: u16 = 0;
const EV_KEY: u16 = 1;
const EV_REL: u16 = 2;
const EV_ABS: u16 = 3;
const SYN_REPORT: u16 = 0;
const REL_WHEEL: u16 = 8;
const ABS_X: u16 = 0;
const ABS_Y: u16 = 1;
const BTN_LEFT: u16 = 272;
const BTN_RIGHT: u16 = 273;
const BTN_MIDDLE: u16 = 274;
const BUS_VIRTUAL: u16 = 0x06;
const INPUT_PROP_POINTER: u16 = 0;

/// Secret-bearing loopback endpoint returned only through the rendezvous socket.
#[derive(Clone, Serialize, Deserialize)]
pub struct DisplayEndpoint {
    /// Transport protocol. Currently always `vnc`.
    pub protocol: String,
    /// Loopback host.
    pub host: String,
    /// Ephemeral loopback TCP port.
    pub port: u16,
    /// Per-launch VNC credential.
    pub password: String,
}

impl fmt::Debug for DisplayEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisplayEndpoint")
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Environment flag consumed by the named-machine start path.
pub const DISPLAY_ENV: &str = "SMOLVM_DISPLAY";

/// Derives the per-machine rendezvous socket without reading secret material.
pub fn endpoint_socket(machine_name: &str) -> PathBuf {
    super::vm_data_dir(machine_name)
        .join("display-runtime")
        .join("endpoint.sock")
}

/// Returns whether a live VMM is accepting rendezvous connections.
pub fn endpoint_is_ready(machine_name: &str) -> bool {
    StdUnixStream::connect(endpoint_socket(machine_name)).is_ok()
}

/// Reads and validates the current secret endpoint without starting a VM.
pub fn read_endpoint(machine_name: &str) -> Result<DisplayEndpoint, String> {
    let mut stream = StdUnixStream::connect(endpoint_socket(machine_name))
        .map_err(|error| format!("display is not available: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("configure display endpoint timeout: {error}"))?;
    let mut bytes = Vec::with_capacity(256);
    stream
        .by_ref()
        .take(4_097)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read display endpoint: {error}"))?;
    decode_endpoint(&bytes)
}

fn decode_endpoint(bytes: &[u8]) -> Result<DisplayEndpoint, String> {
    if bytes.len() > 4_096 {
        return Err("display endpoint exceeded the 4096-byte limit".into());
    }
    let endpoint: DisplayEndpoint = serde_json::from_slice(&bytes)
        .map_err(|_| "display endpoint returned invalid JSON".to_string())?;
    if endpoint.protocol != "vnc"
        || endpoint.host != "127.0.0.1"
        || endpoint.port == 0
        || endpoint.password.is_empty()
    {
        return Err("display endpoint failed validation".into());
    }
    Ok(endpoint)
}

#[derive(Clone)]
struct DisplayBackendConfig {
    frame_tx: mpsc::Sender<FrameEvent>,
    width: u32,
    height: u32,
}

/// Owns callback userdata and the worker that serves one VM display.
pub struct DisplayBridge {
    backend: DisplayBackendConfig,
    keyboard_rx: PollableChannelReciever<InputEvent>,
    pointer_rx: PollableChannelReciever<InputEvent>,
    pointer_options: PointerOptions,
}

impl DisplayBridge {
    /// Starts the bounded RFB and input bridge and waits for endpoint readiness.
    ///
    /// The bridge is boxed before any callback vtable can borrow its fields.
    /// libkrun keeps those userdata pointers for the VM lifetime, so moving the
    /// bridge value after constructing a vtable would invalidate them.
    pub fn start(endpoint_socket: &Path) -> Result<Box<Self>, String> {
        let (frame_tx, frame_rx) = mpsc::channel(FRAME_QUEUE_DEPTH);
        let (keyboard_tx, keyboard_rx) =
            pollable_channel().map_err(|error| format!("create keyboard input queue: {error}"))?;
        let (pointer_tx, pointer_rx) =
            pollable_channel().map_err(|error| format!("create pointer input queue: {error}"))?;
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let endpoint_socket = endpoint_socket.to_path_buf();

        thread::Builder::new()
            .name("smolvm-display".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(format!("create display runtime: {error}")));
                        return;
                    }
                };
                runtime.block_on(run_bridge(
                    endpoint_socket,
                    frame_rx,
                    keyboard_tx,
                    pointer_tx,
                    ready_tx,
                ));
            })
            .map_err(|error| format!("spawn display worker: {error}"))?;

        ready_rx
            .recv()
            .map_err(|error| format!("display worker exited before readiness: {error}"))??;

        Ok(Box::new(Self {
            backend: DisplayBackendConfig {
                frame_tx,
                width: DISPLAY_WIDTH,
                height: DISPLAY_HEIGHT,
            },
            keyboard_rx,
            pointer_rx,
            pointer_options: PointerOptions {
                width: DISPLAY_WIDTH,
                height: DISPLAY_HEIGHT,
            },
        }))
    }

    /// Builds the libkrun display callback vtable.
    pub fn display_backend(&self) -> krun_display::DisplayBackend<'_> {
        RfbDisplayBackend::into_display_backend(Some(&self.backend))
    }

    /// Builds the virtual keyboard capability vtable.
    pub fn keyboard_config(&self) -> krun_input::InputConfigBackend<'_> {
        KeyboardConfig::into_input_config(None)
    }

    /// Builds the virtual keyboard event-provider vtable.
    pub fn keyboard_events(&self) -> krun_input::InputEventProviderBackend<'_> {
        BridgeInputEventProvider::into_input_events(Some(&self.keyboard_rx))
    }

    /// Builds the absolute pointer capability vtable.
    pub fn pointer_config(&self) -> krun_input::InputConfigBackend<'_> {
        PointerConfig::into_input_config(Some(&self.pointer_options))
    }

    /// Builds the absolute pointer event-provider vtable.
    pub fn pointer_events(&self) -> krun_input::InputEventProviderBackend<'_> {
        BridgeInputEventProvider::into_input_events(Some(&self.pointer_rx))
    }
}

enum FrameEvent {
    Update {
        width: u32,
        height: u32,
        format: ResourceFormat,
        damage: Option<Rect>,
        buffer: Vec<u8>,
        recycle: Sender<Vec<u8>>,
    },
}

struct Scanout {
    width: u32,
    height: u32,
    format: ResourceFormat,
    available_tx: Sender<Vec<u8>>,
    available_rx: Receiver<Vec<u8>>,
    current: Option<Vec<u8>>,
}

struct RfbDisplayBackend {
    config: DisplayBackendConfig,
    scanouts: [Option<Scanout>; krun_display::MAX_DISPLAYS],
}

impl DisplayBackendNew<DisplayBackendConfig> for RfbDisplayBackend {
    fn new(userdata: Option<&DisplayBackendConfig>) -> Self {
        Self {
            config: userdata
                .expect("display backend config is required")
                .clone(),
            scanouts: array::from_fn(|_| None),
        }
    }
}

impl DisplayBackendBasicFramebuffer for RfbDisplayBackend {
    fn configure_scanout(
        &mut self,
        scanout_id: u32,
        _display_width: u32,
        _display_height: u32,
        width: u32,
        height: u32,
        format: ResourceFormat,
    ) -> Result<(), DisplayBackendError> {
        let index =
            usize::try_from(scanout_id).map_err(|_| DisplayBackendError::InvalidScanoutId)?;
        if index >= self.scanouts.len()
            || width == 0
            || height == 0
            || width > self.config.width
            || height > self.config.height
            || frame_len(width, height).is_none()
        {
            return Err(DisplayBackendError::InvalidParam);
        }

        let (available_tx, available_rx) = bounded(DISPLAY_BUFFERS);
        for _ in 0..DISPLAY_BUFFERS {
            available_tx
                .try_send(Vec::new())
                .map_err(|_| DisplayBackendError::InternalError)?;
        }
        self.scanouts[index] = Some(Scanout {
            width,
            height,
            format,
            available_tx,
            available_rx,
            current: None,
        });
        Ok(())
    }

    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayBackendError> {
        let index =
            usize::try_from(scanout_id).map_err(|_| DisplayBackendError::InvalidScanoutId)?;
        let slot = self
            .scanouts
            .get_mut(index)
            .ok_or(DisplayBackendError::InvalidScanoutId)?;
        *slot = None;
        Ok(())
    }

    fn alloc_frame(&mut self, scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError> {
        let scanout = self.scanout_mut(scanout_id)?;
        if scanout.current.is_some() {
            return Err(DisplayBackendError::OutOfBuffers);
        }
        let mut buffer = scanout
            .available_rx
            .try_recv()
            .map_err(|error| match error {
                TryRecvError::Empty => DisplayBackendError::OutOfBuffers,
                TryRecvError::Disconnected => DisplayBackendError::InternalError,
            })?;
        let length =
            frame_len(scanout.width, scanout.height).ok_or(DisplayBackendError::InvalidParam)?;
        buffer.resize(length, 0);
        scanout.current = Some(buffer);
        Ok((
            1,
            scanout
                .current
                .as_mut()
                .expect("frame was set")
                .as_mut_slice(),
        ))
    }

    fn present_frame(
        &mut self,
        scanout_id: u32,
        frame_id: u32,
        damage: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        if frame_id != 1 {
            return Err(DisplayBackendError::InvalidParam);
        }
        let frame_tx = self.config.frame_tx.clone();
        let scanout = self.scanout_mut(scanout_id)?;
        let buffer = scanout
            .current
            .take()
            .ok_or(DisplayBackendError::InvalidParam)?;
        let event = FrameEvent::Update {
            width: scanout.width,
            height: scanout.height,
            format: scanout.format,
            damage: damage.copied(),
            buffer,
            recycle: scanout.available_tx.clone(),
        };

        if let Err(error) = frame_tx.try_send(event) {
            let event = match error {
                mpsc::error::TrySendError::Full(event)
                | mpsc::error::TrySendError::Closed(event) => event,
            };
            let FrameEvent::Update {
                buffer, recycle, ..
            } = event;
            let _ = recycle.try_send(buffer);
        }
        Ok(())
    }
}

impl RfbDisplayBackend {
    fn scanout_mut(&mut self, scanout_id: u32) -> Result<&mut Scanout, DisplayBackendError> {
        let index =
            usize::try_from(scanout_id).map_err(|_| DisplayBackendError::InvalidScanoutId)?;
        self.scanouts
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(DisplayBackendError::InvalidScanoutId)
    }
}

async fn run_bridge(
    endpoint_socket: PathBuf,
    mut frame_rx: mpsc::Receiver<FrameEvent>,
    keyboard_tx: PollableChannelSender<InputEvent>,
    pointer_tx: PollableChannelSender<InputEvent>,
    ready_tx: std::sync::mpsc::SyncSender<Result<(), String>>,
) {
    let password: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let (server, mut server_events) = VncServer::new(
        DISPLAY_WIDTH as u16,
        DISPLAY_HEIGHT as u16,
        "SmolVM".into(),
        Some(password.clone()),
    );
    let server = std::sync::Arc::new(server);
    let framebuffer = server.framebuffer().clone();

    let vnc_listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await {
        Ok(listener) => listener,
        Err(error) => {
            let _ = ready_tx.send(Err(format!("bind loopback RFB endpoint: {error}")));
            return;
        }
    };
    let port = match vnc_listener.local_addr() {
        Ok(address) => address.port(),
        Err(error) => {
            let _ = ready_tx.send(Err(format!("read loopback RFB endpoint: {error}")));
            return;
        }
    };
    let _ = std::fs::remove_file(&endpoint_socket);
    let endpoint_listener = match UnixListener::bind(&endpoint_socket) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = ready_tx.send(Err(format!("bind display rendezvous: {error}")));
            return;
        }
    };
    let _endpoint_cleanup = EndpointSocketCleanup(endpoint_socket.clone());
    if let Err(error) =
        std::fs::set_permissions(&endpoint_socket, std::fs::Permissions::from_mode(0o600))
    {
        let _ = ready_tx.send(Err(format!("secure display rendezvous: {error}")));
        return;
    }

    let endpoint = DisplayEndpoint {
        protocol: "vnc".into(),
        host: "127.0.0.1".into(),
        port,
        password,
    };
    let endpoint_json = match serde_json::to_vec(&endpoint) {
        Ok(json) => json,
        Err(error) => {
            let _ = ready_tx.send(Err(format!("encode display endpoint: {error}")));
            return;
        }
    };
    let _ = ready_tx.send(Ok(()));

    let serve_vnc = server.listen_listener(vnc_listener);
    let serve_endpoint = serve_endpoint(endpoint_listener, endpoint_json);
    let frames = async move {
        while let Some(event) = frame_rx.recv().await {
            let FrameEvent::Update {
                width,
                height,
                format,
                damage,
                buffer,
                recycle,
            } = event;
            if let Some((rgba, x, y, crop_width, crop_height)) =
                rgba_damage(&buffer, width, height, format, damage.as_ref())
            {
                let _ = framebuffer
                    .update_cropped(&rgba, x, y, crop_width, crop_height)
                    .await;
            }
            let _ = recycle.try_send(buffer);
        }
    };
    let inputs = async move {
        let mut clients = HashMap::<usize, ClientInputState>::new();
        while let Some(event) = server_events.recv().await {
            match event {
                ServerEvent::ClientConnected { client_id } => {
                    clients.entry(client_id).or_default();
                }
                ServerEvent::ClientDisconnected { client_id } => {
                    if let Some(mut client) = clients.remove(&client_id) {
                        client.release_all(&keyboard_tx, &pointer_tx);
                    }
                }
                ServerEvent::KeyPress {
                    client_id,
                    down,
                    key,
                } => {
                    if let Some(code) = keysym_to_linux(key) {
                        clients
                            .entry(client_id)
                            .or_default()
                            .send_key(code, down, &keyboard_tx);
                    }
                }
                ServerEvent::PointerMove {
                    client_id,
                    x,
                    y,
                    button_mask,
                } => {
                    clients.entry(client_id).or_default().pointer.send(
                        x,
                        y,
                        button_mask,
                        &pointer_tx,
                    );
                }
                _ => {}
            }
        }
    };

    tokio::select! {
        result = serve_vnc => {
            if let Err(error) = result {
                tracing::error!(%error, "SmolVM RFB server stopped");
            }
        }
        _ = serve_endpoint => {}
        _ = frames => {}
        _ = inputs => {}
    }
}

struct EndpointSocketCleanup(PathBuf);

impl Drop for EndpointSocketCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn serve_endpoint(listener: UnixListener, endpoint_json: Vec<u8>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        if !same_user(&stream) {
            continue;
        }
        let mut response = endpoint_json.clone();
        response.push(b'\n');
        let _ = stream.write_all(&response).await;
        let _ = stream.shutdown().await;
    }
}

#[cfg(target_os = "macos")]
fn same_user(stream: &UnixStream) -> bool {
    let mut uid = 0;
    let mut gid = 0;
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    result == 0 && uid == unsafe { libc::geteuid() }
}

#[cfg(target_os = "linux")]
fn same_user(stream: &UnixStream) -> bool {
    let mut credential = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credential as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    result == 0 && credential.uid == unsafe { libc::geteuid() }
}

fn frame_len(width: u32, height: u32) -> Option<usize> {
    let length = usize::try_from(width)
        .ok()?
        .checked_mul(usize::try_from(height).ok()?)?
        .checked_mul(ResourceFormat::BYTES_PER_PIXEL)?;
    (length <= MAX_FRAME_BYTES).then_some(length)
}

fn rgba_damage(
    frame: &[u8],
    width: u32,
    height: u32,
    format: ResourceFormat,
    damage: Option<&Rect>,
) -> Option<(Vec<u8>, u16, u16, u16, u16)> {
    if frame.len() != frame_len(width, height)?
        || width > u16::MAX as u32
        || height > u16::MAX as u32
    {
        return None;
    }
    let (x, y, crop_width, crop_height) = match damage {
        Some(rect)
            if rect.width > 0
                && rect.height > 0
                && rect.x.checked_add(rect.width)? <= width
                && rect.y.checked_add(rect.height)? <= height =>
        {
            (rect.x, rect.y, rect.width, rect.height)
        }
        _ => (0, 0, width, height),
    };
    let output_len = frame_len(crop_width, crop_height)?;
    let mut output = Vec::with_capacity(output_len);
    for row in y..(y + crop_height) {
        for column in x..(x + crop_width) {
            let offset = usize::try_from(row)
                .ok()?
                .checked_mul(usize::try_from(width).ok()?)?
                .checked_add(usize::try_from(column).ok()?)?
                .checked_mul(ResourceFormat::BYTES_PER_PIXEL)?;
            let pixel: [u8; 4] = frame.get(offset..offset + 4)?.try_into().ok()?;
            output.extend_from_slice(&rgba_pixel(pixel, format));
        }
    }
    Some((
        output,
        x as u16,
        y as u16,
        crop_width as u16,
        crop_height as u16,
    ))
}

fn rgba_pixel(pixel: [u8; 4], format: ResourceFormat) -> [u8; 4] {
    match format {
        ResourceFormat::BGRA => [pixel[2], pixel[1], pixel[0], pixel[3]],
        ResourceFormat::BGRX => [pixel[2], pixel[1], pixel[0], 255],
        ResourceFormat::ARGB => [pixel[1], pixel[2], pixel[3], pixel[0]],
        ResourceFormat::XRGB => [pixel[1], pixel[2], pixel[3], 255],
        ResourceFormat::RGBA => pixel,
        ResourceFormat::XBGR => [pixel[3], pixel[2], pixel[1], 255],
        ResourceFormat::ABGR => [pixel[3], pixel[2], pixel[1], pixel[0]],
        ResourceFormat::RGBX => [pixel[0], pixel[1], pixel[2], 255],
    }
}

struct BridgeInputEventProvider {
    rx: PollableChannelReciever<InputEvent>,
}

impl ObjectNew<PollableChannelReciever<InputEvent>> for BridgeInputEventProvider {
    fn new(userdata: Option<&PollableChannelReciever<InputEvent>>) -> Self {
        Self {
            rx: userdata.expect("input event receiver is required").clone(),
        }
    }
}

impl InputEventsImpl for BridgeInputEventProvider {
    fn get_read_notify_fd(&self) -> Result<BorrowedFd<'_>, InputBackendError> {
        Ok(self.rx.as_fd())
    }

    fn next_event(&mut self) -> Result<Option<InputEvent>, InputBackendError> {
        self.rx
            .try_recv()
            .map_err(|_| InputBackendError::InternalError)
    }
}

#[derive(Clone, Copy)]
struct KeyboardConfig;

impl ObjectNew<()> for KeyboardConfig {
    fn new(_userdata: Option<&()>) -> Self {
        Self
    }
}

impl InputQueryConfig for KeyboardConfig {
    fn query_device_name(&self, buffer: &mut [u8]) -> Result<u8, InputBackendError> {
        copy_name(buffer, b"SmolVM Virtual Keyboard")
    }

    fn query_serial_name(&self, buffer: &mut [u8]) -> Result<u8, InputBackendError> {
        copy_name(buffer, b"SMOLVM-KBD")
    }

    fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<(), InputBackendError> {
        *ids = InputDeviceIds {
            bustype: BUS_VIRTUAL,
            vendor: 0x534d,
            product: 1,
            version: 1,
        };
        Ok(())
    }

    fn query_event_capabilities(
        &self,
        event_type: u8,
        buffer: &mut [u8],
    ) -> Result<u8, InputBackendError> {
        match InputEventType::try_from(event_type as u16) {
            Ok(InputEventType::Syn) => set_bits(buffer, &[SYN_REPORT]),
            Ok(InputEventType::Key) => {
                let keys: Vec<u16> = (1..=248).collect();
                set_bits(buffer, &keys)
            }
            _ => Ok(0),
        }
    }

    fn query_abs_info(&self, _axis: u8, _info: &mut InputAbsInfo) -> Result<(), InputBackendError> {
        Ok(())
    }

    fn query_properties(&self, _buffer: &mut [u8]) -> Result<u8, InputBackendError> {
        Ok(0)
    }
}

#[derive(Clone, Copy)]
struct PointerOptions {
    width: u32,
    height: u32,
}

#[derive(Clone, Copy)]
struct PointerConfig(PointerOptions);

impl ObjectNew<PointerOptions> for PointerConfig {
    fn new(userdata: Option<&PointerOptions>) -> Self {
        Self(*userdata.expect("pointer options are required"))
    }
}

impl InputQueryConfig for PointerConfig {
    fn query_device_name(&self, buffer: &mut [u8]) -> Result<u8, InputBackendError> {
        copy_name(buffer, b"SmolVM Absolute Pointer")
    }

    fn query_serial_name(&self, buffer: &mut [u8]) -> Result<u8, InputBackendError> {
        copy_name(buffer, b"SMOLVM-PTR")
    }

    fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<(), InputBackendError> {
        *ids = InputDeviceIds {
            bustype: BUS_VIRTUAL,
            vendor: 0x534d,
            product: 2,
            version: 1,
        };
        Ok(())
    }

    fn query_event_capabilities(
        &self,
        event_type: u8,
        buffer: &mut [u8],
    ) -> Result<u8, InputBackendError> {
        match InputEventType::try_from(event_type as u16) {
            Ok(InputEventType::Syn) => set_bits(buffer, &[SYN_REPORT]),
            Ok(InputEventType::Key) => set_bits(buffer, &[BTN_LEFT, BTN_RIGHT, BTN_MIDDLE]),
            Ok(InputEventType::Abs) => set_bits(buffer, &[ABS_X, ABS_Y]),
            Ok(InputEventType::Rel) => set_bits(buffer, &[REL_WHEEL]),
            _ => Ok(0),
        }
    }

    fn query_abs_info(&self, axis: u8, info: &mut InputAbsInfo) -> Result<(), InputBackendError> {
        let max = match axis as u16 {
            ABS_X => self.0.width.saturating_sub(1),
            ABS_Y => self.0.height.saturating_sub(1),
            _ => 0,
        };
        *info = InputAbsInfo {
            min: 0,
            max,
            fuzz: 0,
            flat: 0,
            res: 0,
        };
        Ok(())
    }

    fn query_properties(&self, buffer: &mut [u8]) -> Result<u8, InputBackendError> {
        set_bits(buffer, &[INPUT_PROP_POINTER])
    }
}

fn copy_name(buffer: &mut [u8], name: &[u8]) -> Result<u8, InputBackendError> {
    let length = buffer.len().min(name.len()).min(u8::MAX as usize);
    buffer[..length].copy_from_slice(&name[..length]);
    Ok(length as u8)
}

fn set_bits(buffer: &mut [u8], bits: &[u16]) -> Result<u8, InputBackendError> {
    let mut last = None;
    for bit in bits {
        let byte = usize::from(*bit / 8);
        if byte >= buffer.len() {
            return Err(InputBackendError::InvalidParam);
        }
        buffer[byte] |= 1 << (*bit % 8);
        last = Some(last.map_or(byte, |current: usize| current.max(byte)));
    }
    Ok(last.map_or(0, |byte| (byte + 1).min(u8::MAX as usize) as u8))
}

#[derive(Default)]
struct PointerState {
    buttons: u8,
}

impl PointerState {
    fn send(&mut self, x: u16, y: u16, buttons: u8, sender: &PollableChannelSender<InputEvent>) {
        let mut events = vec![
            input_event(
                EV_ABS,
                ABS_X,
                u32::from(x).min(DISPLAY_WIDTH.saturating_sub(1)),
            ),
            input_event(
                EV_ABS,
                ABS_Y,
                u32::from(y).min(DISPLAY_HEIGHT.saturating_sub(1)),
            ),
        ];
        for (mask, code) in [(1, BTN_LEFT), (2, BTN_MIDDLE), (4, BTN_RIGHT)] {
            if self.buttons & mask != buttons & mask {
                events.push(input_event(EV_KEY, code, u32::from(buttons & mask != 0)));
            }
        }
        if buttons & 8 != 0 {
            events.push(input_event(EV_REL, REL_WHEEL, 1));
        }
        if buttons & 16 != 0 {
            events.push(input_event(EV_REL, REL_WHEEL, u32::MAX));
        }
        events.push(input_event(EV_SYN, SYN_REPORT, 0));
        self.buttons = buttons & 0b0000_0111;
        let _ = sender.send_many(events);
    }

    fn release_all(&mut self, sender: &PollableChannelSender<InputEvent>) {
        if self.buttons == 0 {
            return;
        }
        let mut events = Vec::with_capacity(4);
        for (mask, code) in [(1, BTN_LEFT), (2, BTN_MIDDLE), (4, BTN_RIGHT)] {
            if self.buttons & mask != 0 {
                events.push(input_event(EV_KEY, code, 0));
            }
        }
        events.push(input_event(EV_SYN, SYN_REPORT, 0));
        self.buttons = 0;
        let _ = sender.send_many(events);
    }
}

#[derive(Default)]
struct ClientInputState {
    keys: HashSet<u16>,
    pointer: PointerState,
}

impl ClientInputState {
    fn send_key(&mut self, code: u16, down: bool, sender: &PollableChannelSender<InputEvent>) {
        let changed = if down {
            self.keys.insert(code)
        } else {
            self.keys.remove(&code)
        };
        if changed {
            let _ = sender.send_many([
                input_event(EV_KEY, code, u32::from(down)),
                input_event(EV_SYN, SYN_REPORT, 0),
            ]);
        }
    }

    fn release_all(
        &mut self,
        keyboard: &PollableChannelSender<InputEvent>,
        pointer: &PollableChannelSender<InputEvent>,
    ) {
        if !self.keys.is_empty() {
            let mut events: Vec<_> = self
                .keys
                .drain()
                .map(|code| input_event(EV_KEY, code, 0))
                .collect();
            events.push(input_event(EV_SYN, SYN_REPORT, 0));
            let _ = keyboard.send_many(events);
        }
        self.pointer.release_all(pointer);
    }
}

fn input_event(event_type: u16, code: u16, value: u32) -> InputEvent {
    InputEvent {
        type_: event_type,
        code,
        value,
    }
}

fn keysym_to_linux(keysym: u32) -> Option<u16> {
    let lower = if (b'A' as u32..=b'Z' as u32).contains(&keysym) {
        keysym + 32
    } else {
        keysym
    };
    Some(match lower {
        0x0061 => 30, // a
        0x0062 => 48,
        0x0063 => 46,
        0x0064 => 32,
        0x0065 => 18,
        0x0066 => 33,
        0x0067 => 34,
        0x0068 => 35,
        0x0069 => 23,
        0x006a => 36,
        0x006b => 37,
        0x006c => 38,
        0x006d => 50,
        0x006e => 49,
        0x006f => 24,
        0x0070 => 25,
        0x0071 => 16,
        0x0072 => 19,
        0x0073 => 31,
        0x0074 => 20,
        0x0075 => 22,
        0x0076 => 47,
        0x0077 => 17,
        0x0078 => 45,
        0x0079 => 21,
        0x007a => 44,          // z
        0x0031 | 0x0021 => 2,  // 1 !
        0x0032 | 0x0040 => 3,  // 2 @
        0x0033 | 0x0023 => 4,  // 3 #
        0x0034 | 0x0024 => 5,  // 4 $
        0x0035 | 0x0025 => 6,  // 5 %
        0x0036 | 0x005e => 7,  // 6 ^
        0x0037 | 0x0026 => 8,  // 7 &
        0x0038 | 0x002a => 9,  // 8 *
        0x0039 | 0x0028 => 10, // 9 (
        0x0030 | 0x0029 => 11, // 0 )
        0x002d | 0x005f => 12, // - _
        0x003d | 0x002b => 13, // = +
        0x005b | 0x007b => 26, // [ {
        0x005d | 0x007d => 27, // ] }
        0x003b | 0x003a => 39, // ; :
        0x0027 | 0x0022 => 40, // ' "
        0x0060 | 0x007e => 41, // ` ~
        0x005c | 0x007c => 43, // \ |
        0x002c | 0x003c => 51, // , <
        0x002e | 0x003e => 52, // . >
        0x002f | 0x003f => 53, // / ?
        0x0020 => 57,
        0xff08 => 14, // Backspace
        0xff09 => 15, // Tab
        0xff0d => 28, // Return
        0xff1b => 1,  // Escape
        0xff50 => 102,
        0xff51 => 105,
        0xff52 => 103,
        0xff53 => 106,
        0xff54 => 108,
        0xff55 => 104,
        0xff56 => 109,
        0xff57 => 107,
        0xffff => 111,
        0xffe1 => 42,
        0xffe2 => 54,
        0xffe3 => 29,
        0xffe4 => 97,
        0xffe7 | 0xffe9 => 56,
        0xffe8 | 0xffea => 100,
        0xffbe..=0xffc9 => 59 + (lower - 0xffbe) as u16,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_length_is_checked_and_bounded() {
        assert_eq!(frame_len(1_440, 900), Some(5_184_000));
        assert_eq!(frame_len(u32::MAX, u32::MAX), None);
        assert_eq!(frame_len(16_384, 16_384), None);
    }

    #[test]
    fn converts_bgra_damage_to_rgba() {
        let frame = vec![3, 2, 1, 4, 30, 20, 10, 40];
        let damage = Rect {
            x: 1,
            y: 0,
            width: 1,
            height: 1,
        };
        let (rgba, x, y, width, height) =
            rgba_damage(&frame, 2, 1, ResourceFormat::BGRA, Some(&damage)).unwrap();
        assert_eq!(rgba, vec![10, 20, 30, 40]);
        assert_eq!((x, y, width, height), (1, 0, 1, 1));
    }

    #[test]
    fn converts_every_supported_pixel_format_to_rgba() {
        for (format, input, expected) in [
            (ResourceFormat::BGRA, [3, 2, 1, 4], [1, 2, 3, 4]),
            (ResourceFormat::BGRX, [3, 2, 1, 4], [1, 2, 3, 255]),
            (ResourceFormat::ARGB, [4, 1, 2, 3], [1, 2, 3, 4]),
            (ResourceFormat::XRGB, [4, 1, 2, 3], [1, 2, 3, 255]),
            (ResourceFormat::RGBA, [1, 2, 3, 4], [1, 2, 3, 4]),
            (ResourceFormat::XBGR, [4, 3, 2, 1], [1, 2, 3, 255]),
            (ResourceFormat::ABGR, [4, 3, 2, 1], [1, 2, 3, 4]),
            (ResourceFormat::RGBX, [1, 2, 3, 4], [1, 2, 3, 255]),
        ] {
            assert_eq!(rgba_pixel(input, format), expected);
        }
    }

    #[test]
    fn maps_common_rfb_keysyms_to_linux_keys() {
        assert_eq!(keysym_to_linux('a' as u32), Some(30));
        assert_eq!(keysym_to_linux('A' as u32), Some(30));
        assert_eq!(keysym_to_linux('-' as u32), Some(12));
        assert_eq!(keysym_to_linux('_' as u32), Some(12));
        assert_eq!(keysym_to_linux('/' as u32), Some(53));
        assert_eq!(keysym_to_linux('?' as u32), Some(53));
        assert_eq!(keysym_to_linux(0xff0d), Some(28));
        assert_eq!(keysym_to_linux(0x10ffff), None);
    }

    #[test]
    fn endpoint_debug_output_never_contains_the_password() {
        let endpoint = DisplayEndpoint {
            protocol: "vnc".into(),
            host: "127.0.0.1".into(),
            port: 59_001,
            password: "secret42".into(),
        };
        let output = format!("{endpoint:?}");
        assert!(!output.contains("secret42"));
        assert!(output.contains("[REDACTED]"));
    }

    #[test]
    fn endpoint_decoder_accepts_only_bounded_loopback_vnc() {
        let valid = br#"{"protocol":"vnc","host":"127.0.0.1","port":5901,"password":"secret42"}"#;
        assert_eq!(decode_endpoint(valid).unwrap().port, 5901);

        for invalid in [
            br#"{"protocol":"http","host":"127.0.0.1","port":5901,"password":"secret42"}"#
                .as_slice(),
            br#"{"protocol":"vnc","host":"0.0.0.0","port":5901,"password":"secret42"}"#.as_slice(),
            br#"{"protocol":"vnc","host":"127.0.0.1","port":0,"password":"secret42"}"#.as_slice(),
            br#"{"protocol":"vnc","host":"127.0.0.1","port":5901,"password":""}"#.as_slice(),
            br#"not-json-secret42"#.as_slice(),
        ] {
            let error = decode_endpoint(invalid).unwrap_err();
            assert!(!error.contains("secret42"));
        }

        let oversized = vec![b'x'; 4_097];
        assert!(decode_endpoint(&oversized)
            .unwrap_err()
            .contains("4096-byte"));
    }

    #[test]
    fn full_frame_queue_recycles_the_dropped_buffer() {
        let (frame_tx, frame_rx) = mpsc::channel(FRAME_QUEUE_DEPTH);
        let config = DisplayBackendConfig {
            frame_tx,
            width: 4,
            height: 4,
        };
        let mut backend = RfbDisplayBackend::new(Some(&config));
        backend
            .configure_scanout(0, 4, 4, 4, 4, ResourceFormat::RGBA)
            .unwrap();

        for _ in 0..=FRAME_QUEUE_DEPTH {
            backend.alloc_frame(0).unwrap();
            backend.present_frame(0, 1, None).unwrap();
        }

        assert_eq!(frame_rx.len(), FRAME_QUEUE_DEPTH);
        assert!(backend.alloc_frame(0).is_ok());
    }

    #[test]
    fn boxed_bridge_keeps_callback_userdata_stable_when_owner_moves() {
        let (frame_tx, _frame_rx) = mpsc::channel(FRAME_QUEUE_DEPTH);
        let (_keyboard_tx, keyboard_rx) = pollable_channel().unwrap();
        let (_pointer_tx, pointer_rx) = pollable_channel().unwrap();
        let bridge = Box::new(DisplayBridge {
            backend: DisplayBackendConfig {
                frame_tx,
                width: DISPLAY_WIDTH,
                height: DISPLAY_HEIGHT,
            },
            keyboard_rx,
            pointer_rx,
            pointer_options: PointerOptions {
                width: DISPLAY_WIDTH,
                height: DISPLAY_HEIGHT,
            },
        });

        let userdata = bridge.display_backend().create_userdata;
        let moved_owner = Some(bridge);
        let expected = std::ptr::from_ref(&moved_owner.as_ref().unwrap().backend).cast();
        assert_eq!(userdata, expected);
    }

    #[test]
    fn disconnect_releases_pressed_keys_and_pointer_buttons() {
        let (keyboard_tx, keyboard_rx) = pollable_channel().unwrap();
        let (pointer_tx, pointer_rx) = pollable_channel().unwrap();
        let mut client = ClientInputState::default();

        client.send_key(30, true, &keyboard_tx);
        client.pointer.send(10, 20, 1, &pointer_tx);
        while keyboard_rx.try_recv().unwrap().is_some() {}
        while pointer_rx.try_recv().unwrap().is_some() {}
        client.release_all(&keyboard_tx, &pointer_tx);

        let key_release = keyboard_rx.try_recv().unwrap().unwrap();
        assert_eq!(
            (key_release.type_, key_release.code, key_release.value),
            (EV_KEY, 30, 0)
        );
        let pointer_release = pointer_rx.try_recv().unwrap().unwrap();
        assert_eq!(
            (
                pointer_release.type_,
                pointer_release.code,
                pointer_release.value
            ),
            (EV_KEY, BTN_LEFT, 0)
        );
    }
}
