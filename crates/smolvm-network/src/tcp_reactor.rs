//! One host thread pumping every TCP flow of a machine.
//!
//! The relay used to give each guest TCP flow its own host thread and its own
//! poller. That costs three host file descriptors and a thread per flow, so a
//! guest opening thousands of connections at once (a package manager behind a
//! local proxy) ran into the per-process thread and file limits long before
//! its own kernel's. Here every flow's host socket sits in one poller and one
//! thread drives each flow's [`RelayPump`] when its socket is ready or the
//! poll loop wakes it, so a flow costs exactly its host socket.
//!
//! Connecting is non-blocking too. Only the targets that must talk to another
//! host process before they can carry guest bytes (a credential interceptor,
//! an egress decider) open on a short-lived thread, then join the reactor.

use crate::queues::WakePipe;
use crate::tcp_relay::{
    open_relay_target, prepare_host_stream, NewTcpConnection, OpeningWatch, PumpOutcome,
    RelayExitMode, RelayExitState, RelayFlow, RelayPump, RelayTarget,
};
use crate::virtio_net_log;
use polling::{Event, Events, Poller};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Bounds on the interceptor-free direct dial a mediated "allow" makes.
const DIRECT_MEDIATED_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How often the reactor looks at every flow for timers and for errors a
/// kqueue host never reports on a socket nobody reads.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// Bytes read from a host socket at a time. Larger than a relay thread's
/// reads: the reactor pays a wake round trip whenever a flow's channel to the
/// poll loop fills, so fewer, larger payloads keep one fast stream moving.
const REACTOR_READ_BYTES: usize = 64 * 1024;
/// Pump rounds one flow gets before the next flow's turn.
const PUMP_BUDGET: usize = 16;
/// The shortest gap between two "host refused a socket" warnings.
const HOST_LIMIT_WARNING_INTERVAL: Duration = Duration::from_secs(10);

/// Wakes the host relay of one flow.
#[derive(Clone, Debug)]
pub enum RelayWaker {
    /// A flow on its own relay thread, which waits on this poller.
    Standalone(WakePipe),
    /// A flow on the shared reactor.
    Reactor { shared: Arc<Shared>, id: u64 },
}

impl RelayWaker {
    /// A waker for a flow that gets its own relay thread.
    pub fn standalone() -> Self {
        RelayWaker::Standalone(WakePipe::new())
    }

    /// Wake the flow's relay.
    pub fn wake(&self) {
        match self {
            RelayWaker::Standalone(wake) => wake.wake(),
            RelayWaker::Reactor { shared, id } => {
                if let Ok(mut dirty) = shared.dirty.lock() {
                    dirty.push(*id);
                }
                let _ = shared.poller.notify();
            }
        }
    }

    /// The poller a dedicated relay thread waits on.
    pub(crate) fn standalone_poller(&self) -> Option<Arc<Poller>> {
        match self {
            RelayWaker::Standalone(wake) => Some(wake.poller().clone()),
            RelayWaker::Reactor { .. } => None,
        }
    }
}

/// State the poll loop shares with the reactor thread.
pub struct Shared {
    poller: Poller,
    /// Flows handed over by the poll loop, or back from a setup thread.
    inbox: Mutex<Vec<Arrival>>,
    /// Flows the poll loop woke.
    dirty: Mutex<Vec<u64>>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

enum Arrival {
    Adopt(u64, Box<NewTcpConnection>),
    Opened {
        id: u64,
        result: io::Result<OpenedFlow>,
    },
}

struct OpenedFlow {
    stream: TcpStream,
    pending_guest_data: Option<(Vec<u8>, usize)>,
    from_smoltcp: Receiver<Vec<u8>>,
}

/// Handle the poll loop keeps on its machine's reactor.
#[derive(Clone, Debug)]
pub struct RelayReactor {
    shared: Arc<Shared>,
}

impl RelayReactor {
    /// Start the reactor thread for one machine's NIC. `relay_wake` wakes the
    /// poll loop; the thread exits once `shutdown` reports true.
    pub fn start(
        relay_wake: Arc<WakePipe>,
        shutdown: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            poller: Poller::new()?,
            inbox: Mutex::new(Vec::new()),
            dirty: Mutex::new(Vec::new()),
        });
        let thread_shared = shared.clone();
        thread::Builder::new()
            .name("smolvm-tcp-relay".into())
            .spawn(move || Reactor::new(thread_shared, relay_wake).run(&*shutdown))?;
        Ok(Self { shared })
    }

    /// A waker for the flow the poll loop numbers `id`.
    pub fn waker(&self, id: u64) -> RelayWaker {
        RelayWaker::Reactor {
            shared: self.shared.clone(),
            id,
        }
    }

    /// Take over an established guest flow.
    pub fn adopt(&self, connection: NewTcpConnection) {
        let id = match &connection.proxy_wake {
            RelayWaker::Reactor { id, .. } => *id,
            RelayWaker::Standalone(_) => {
                // Not numbered by this reactor: its wakes would never reach it.
                connection.exit_state.store(RelayExitMode::Abort);
                return;
            }
        };
        self.push(Arrival::Adopt(id, Box::new(connection)));
    }

    fn push(&self, arrival: Arrival) {
        push(&self.shared, arrival);
    }
}

fn push(shared: &Shared, arrival: Arrival) {
    if let Ok(mut inbox) = shared.inbox.lock() {
        inbox.push(arrival);
    }
    let _ = shared.poller.notify();
}

/// Everything a flow needs from the poll loop before its host socket is up.
struct Waiting {
    from_smoltcp: Receiver<Vec<u8>>,
    to_smoltcp: SyncSender<Vec<u8>>,
    mediated: bool,
    opening: Option<OpeningWatch>,
}

enum Stage {
    /// Non-blocking connect in flight; the socket is in the poller.
    Connecting {
        socket: Socket,
        deadline: Option<Instant>,
        waiting: Waiting,
    },
    /// A setup thread owns the flow's host side until it reports back.
    Opening {
        to_smoltcp: SyncSender<Vec<u8>>,
        mediated: bool,
        opening: Option<OpeningWatch>,
    },
    /// Bytes flow; the stream is in the poller.
    Relaying(RelayPump),
}

struct Flow {
    exit_state: RelayExitState,
    stage: Stage,
    /// The host socket is armed with no interest, waiting only for an error
    /// or hang-up: from then on, and only then, an event on it means one.
    errors_only: bool,
}

struct Reactor {
    shared: Arc<Shared>,
    relay_wake: Arc<WakePipe>,
    flows: HashMap<u64, Flow>,
    /// Flows that still had work when their budget ran out.
    ready: VecDeque<u64>,
    read_buffer: Vec<u8>,
    last_sweep: Instant,
    host_refusals: u64,
    host_refusals_reported: u64,
    last_host_warning: Option<Instant>,
}

impl Reactor {
    fn new(shared: Arc<Shared>, relay_wake: Arc<WakePipe>) -> Self {
        Self {
            shared,
            relay_wake,
            flows: HashMap::new(),
            ready: VecDeque::new(),
            read_buffer: vec![0u8; REACTOR_READ_BYTES],
            last_sweep: Instant::now(),
            host_refusals: 0,
            host_refusals_reported: 0,
            last_host_warning: None,
        }
    }

    fn run(mut self, shutdown: &dyn Fn() -> bool) {
        let mut events = Events::new();
        let mut woken: Vec<(u64, bool)> = Vec::new();
        loop {
            if shutdown() {
                return;
            }
            let timeout = if self.ready.is_empty() {
                SWEEP_INTERVAL.saturating_sub(self.last_sweep.elapsed())
            } else {
                Duration::ZERO
            };
            events.clear();
            let _ = self.shared.poller.wait(&mut events, Some(timeout));

            let arrivals = std::mem::take(&mut *self.shared.inbox.lock().unwrap());
            for arrival in arrivals {
                self.arrive(arrival);
            }
            woken.clear();
            woken.extend(events.iter().map(|event| (event.key as u64, true)));
            woken.extend(
                std::mem::take(&mut *self.shared.dirty.lock().unwrap())
                    .into_iter()
                    .map(|id| (id, false)),
            );
            woken.extend(self.ready.drain(..).map(|id| (id, false)));
            for &(id, from_socket) in &woken {
                self.drive(id, from_socket);
            }
            if self.last_sweep.elapsed() >= SWEEP_INTERVAL {
                self.sweep();
                self.last_sweep = Instant::now();
            }
        }
    }

    fn arrive(&mut self, arrival: Arrival) {
        match arrival {
            Arrival::Adopt(id, connection) => self.adopt(id, *connection),
            Arrival::Opened { id, result } => {
                let Some(flow) = self.flows.remove(&id) else {
                    return;
                };
                let Stage::Opening {
                    to_smoltcp,
                    mediated,
                    opening,
                } = flow.stage
                else {
                    self.flows.insert(id, flow);
                    return;
                };
                let started = result.and_then(|opened| {
                    prepare_host_stream(&opened.stream)?;
                    RelayPump::new(
                        opened.stream,
                        opened.from_smoltcp,
                        to_smoltcp,
                        RelayFlow {
                            mediated,
                            pending_guest_data: opened.pending_guest_data,
                            opening,
                        },
                    )
                });
                match started.and_then(|pump| self.register(id, pump)) {
                    Ok(pump) => {
                        self.flows.insert(
                            id,
                            Flow {
                                exit_state: flow.exit_state,
                                stage: Stage::Relaying(pump),
                                errors_only: false,
                            },
                        );
                        self.ready.push_back(id);
                    }
                    Err(err) => self.fail(id, flow.exit_state, &err),
                }
            }
        }
    }

    fn adopt(&mut self, id: u64, connection: NewTcpConnection) {
        let NewTcpConnection {
            destination,
            relay_target,
            from_smoltcp,
            to_smoltcp,
            exit_state,
            watch_opening,
            ..
        } = connection;
        let mediated = relay_target.is_mediated();
        let opening = watch_opening.map(|egress| OpeningWatch::new(egress, destination));
        let waiting = Waiting {
            from_smoltcp,
            to_smoltcp,
            mediated,
            opening,
        };
        match relay_target {
            RelayTarget::Connect(address) => self.connect(id, exit_state, address, None, waiting),
            RelayTarget::DirectMediated(address) => self.connect(
                id,
                exit_state,
                address,
                Some(Instant::now() + DIRECT_MEDIATED_CONNECT_TIMEOUT),
                waiting,
            ),
            RelayTarget::Attached(stream) => {
                let started = prepare_host_stream(&stream).and_then(|()| {
                    RelayPump::new(
                        stream,
                        waiting.from_smoltcp,
                        waiting.to_smoltcp,
                        RelayFlow {
                            mediated,
                            pending_guest_data: None,
                            opening: waiting.opening,
                        },
                    )
                });
                self.start_relaying(id, exit_state, started);
            }
            target @ (RelayTarget::Intercept { .. } | RelayTarget::Mediated { .. }) => {
                // These talk to another host process before the flow can carry
                // guest bytes; that exchange blocks, so it runs off the reactor.
                let Waiting {
                    from_smoltcp,
                    to_smoltcp,
                    mediated,
                    opening,
                } = waiting;
                let thread_exit_state = exit_state.clone();
                self.flows.insert(
                    id,
                    Flow {
                        exit_state,
                        stage: Stage::Opening {
                            to_smoltcp,
                            mediated,
                            opening,
                        },
                        errors_only: false,
                    },
                );
                let shared = self.shared.clone();
                let relay_wake = self.relay_wake.clone();
                let spawned =
                    thread::Builder::new()
                        .name("smolvm-tcp-open".into())
                        .spawn(move || {
                            let result = open_relay_target(
                                target,
                                &from_smoltcp,
                                &relay_wake,
                                &thread_exit_state,
                            )
                            .map(|(stream, pending_guest_data)| OpenedFlow {
                                stream,
                                pending_guest_data,
                                from_smoltcp,
                            });
                            push(&shared, Arrival::Opened { id, result });
                        });
                if let Err(err) = spawned {
                    if let Some(flow) = self.flows.remove(&id) {
                        self.fail(id, flow.exit_state, &err);
                    }
                }
            }
        }
    }

    fn start_relaying(
        &mut self,
        id: u64,
        exit_state: RelayExitState,
        started: io::Result<RelayPump>,
    ) {
        match started.and_then(|pump| self.register(id, pump)) {
            Ok(pump) => {
                self.flows.insert(
                    id,
                    Flow {
                        exit_state,
                        stage: Stage::Relaying(pump),
                        errors_only: false,
                    },
                );
                self.ready.push_back(id);
            }
            Err(err) => self.fail(id, exit_state, &err),
        }
    }

    /// Put a pump's stream in the poller under the flow's id.
    fn register(&mut self, id: u64, pump: RelayPump) -> io::Result<RelayPump> {
        // SAFETY: the stream is deleted from the poller in `finish` (or below)
        // before it is dropped.
        unsafe {
            self.shared
                .poller
                .add(&pump.stream, Event::none(id as usize))?
        };
        Ok(pump)
    }

    fn connect(
        &mut self,
        id: u64,
        exit_state: RelayExitState,
        address: SocketAddr,
        deadline: Option<Instant>,
        waiting: Waiting,
    ) {
        let socket = match Socket::new(
            Domain::for_address(address),
            Type::STREAM,
            Some(Protocol::TCP),
        ) {
            Ok(socket) => socket,
            Err(err) => {
                self.note_host_refusal(&err);
                return self.fail(id, exit_state, &err);
            }
        };
        let dialed = socket.set_nonblocking(true).and_then(|()| {
            match socket.connect(&SockAddr::from(address)) {
                Ok(()) => Ok(()),
                Err(err) if connect_in_progress(&err) => Ok(()),
                Err(err) => Err(err),
            }
        });
        if let Err(err) = dialed {
            self.note_host_refusal(&err);
            return self.fail(id, exit_state, &err);
        }
        // SAFETY: deleted from the poller in `finish` before the socket drops.
        if let Err(err) = unsafe {
            self.shared
                .poller
                .add(&socket, Event::writable(id as usize))
        } {
            return self.fail(id, exit_state, &err);
        }
        self.flows.insert(
            id,
            Flow {
                exit_state,
                stage: Stage::Connecting {
                    socket,
                    deadline,
                    waiting,
                },
                errors_only: false,
            },
        );
    }

    /// Advance one flow after its socket fired (`from_socket`) or it was woken.
    fn drive(&mut self, id: u64, from_socket: bool) {
        let Some(flow) = self.flows.get_mut(&id) else {
            return;
        };
        match &mut flow.stage {
            Stage::Opening { .. } => {}
            Stage::Connecting { socket, .. } => {
                if !from_socket {
                    return;
                }
                match socket.take_error() {
                    Ok(None) => {}
                    Ok(Some(err)) | Err(err) => return self.finish_with_error(id, &err),
                }
                if socket.peer_addr().is_err() {
                    // Woken before the handshake finished; wait for writability.
                    let _ = self
                        .shared
                        .poller
                        .modify(&*socket, Event::writable(id as usize));
                    return;
                }
                let Some(flow) = self.flows.remove(&id) else {
                    return;
                };
                let Stage::Connecting {
                    socket, waiting, ..
                } = flow.stage
                else {
                    unreachable!("stage checked above");
                };
                let stream: TcpStream = socket.into();
                let started = prepare_host_stream(&stream).and_then(|()| {
                    RelayPump::new(
                        stream,
                        waiting.from_smoltcp,
                        waiting.to_smoltcp,
                        RelayFlow {
                            mediated: waiting.mediated,
                            pending_guest_data: None,
                            opening: waiting.opening,
                        },
                    )
                });
                match started {
                    // Already registered under this id while connecting.
                    Ok(pump) => {
                        self.flows.insert(
                            id,
                            Flow {
                                exit_state: flow.exit_state,
                                stage: Stage::Relaying(pump),
                                errors_only: false,
                            },
                        );
                        self.drive(id, false);
                    }
                    Err(err) => self.fail(id, flow.exit_state, &err),
                }
            }
            Stage::Relaying(pump) => {
                // Only an event that arrives while the socket waits for errors
                // alone is a hang-up. The readable event that carried the
                // host's FIN is not one: treating it as such reset the guest's
                // connection while it was still reading the host's last bytes.
                let hung_up = from_socket && flow.errors_only;
                flow.errors_only = false;
                let outcome = pump.pump(
                    &mut self.read_buffer,
                    &self.relay_wake,
                    &flow.exit_state,
                    PUMP_BUDGET,
                );
                match outcome {
                    Ok(PumpOutcome::Busy) => self.ready.push_back(id),
                    Ok(PumpOutcome::Finished(mode)) => self.finish(id, mode),
                    Ok(PumpOutcome::Idle { read, write }) => {
                        if pump.only_waiting_for_guest() {
                            if let Err(err) = pump.check_host_error(hung_up) {
                                return self.finish_with_error(id, &err);
                            }
                            // Armed with no interest: epoll still reports an
                            // error or hang-up on it.
                            let _ = self
                                .shared
                                .poller
                                .modify(&pump.stream, Event::none(id as usize));
                            flow.errors_only = true;
                        } else if read || write {
                            let _ = self
                                .shared
                                .poller
                                .modify(&pump.stream, Event::new(id as usize, read, write));
                        }
                        // Otherwise the host->guest channel is full: the
                        // socket stays disarmed until the poll loop drains the
                        // channel and wakes this flow.
                    }
                    Err(err) => self.finish_with_error(id, &err),
                }
            }
        }
    }

    /// Timers, and errors kqueue never reports on a socket nobody reads.
    fn sweep(&mut self) {
        let now = Instant::now();
        let mut ended = Vec::new();
        for (&id, flow) in &self.flows {
            match &flow.stage {
                Stage::Connecting {
                    deadline: Some(deadline),
                    ..
                } if now >= *deadline => ended.push((
                    id,
                    io::Error::new(io::ErrorKind::TimedOut, "host TCP connect timed out"),
                )),
                Stage::Relaying(pump) if pump.expired() => ended.push((
                    id,
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "mediated TCP flow lifetime expired",
                    ),
                )),
                Stage::Relaying(pump) if pump.only_waiting_for_guest() => {
                    if let Err(err) = pump.check_host_error(false) {
                        ended.push((id, err));
                    }
                }
                _ => {}
            }
        }
        for (id, err) in ended {
            self.finish_with_error(id, &err);
        }
    }

    fn finish_with_error(&mut self, id: u64, err: &io::Error) {
        tracing::debug!(id, error = %err, "virtio-net: host TCP relay failed");
        self.finish(id, RelayExitMode::Abort);
    }

    /// End a flow: drop its host socket and tell the poll loop how it ended.
    fn finish(&mut self, id: u64, mode: RelayExitMode) {
        let Some(flow) = self.flows.remove(&id) else {
            return;
        };
        match &flow.stage {
            Stage::Connecting { socket, .. } => {
                let _ = self.shared.poller.delete(socket);
            }
            Stage::Relaying(pump) => {
                let _ = self.shared.poller.delete(&pump.stream);
            }
            Stage::Opening { .. } => {}
        }
        flow.exit_state.store(mode);
        flow.exit_state.notify(&self.relay_wake);
    }

    /// A flow that never got a registered host socket.
    fn fail(&mut self, id: u64, exit_state: RelayExitState, err: &io::Error) {
        tracing::debug!(id, error = %err, "virtio-net: host TCP relay could not start");
        self.flows.remove(&id);
        exit_state.store(RelayExitMode::Abort);
        exit_state.notify(&self.relay_wake);
    }

    /// Say in the machine log when the host refuses a socket for want of
    /// file descriptors or buffers: the guest only sees its connection reset.
    fn note_host_refusal(&mut self, err: &io::Error) {
        if !is_resource_exhaustion(err) {
            return;
        }
        self.host_refusals = self.host_refusals.saturating_add(1);
        let now = Instant::now();
        if self
            .last_host_warning
            .is_some_and(|at| now.duration_since(at) < HOST_LIMIT_WARNING_INTERVAL)
        {
            return;
        }
        virtio_net_log!(
            "virtio-net: the host refused a socket for a guest TCP connection ({}) with {} open; {}; \
             {} refused since the last report",
            err,
            self.flows.len(),
            host_limit_hint(err),
            self.host_refusals - self.host_refusals_reported
        );
        self.host_refusals_reported = self.host_refusals;
        self.last_host_warning = Some(now);
    }
}

fn connect_in_progress(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(unix)]
    {
        err.raw_os_error() == Some(libc::EINPROGRESS)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Out of file descriptors, kernel buffers or local ports, as opposed to a
/// destination that refused or could not be reached.
pub(crate) fn is_resource_exhaustion(err: &io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(
            err.raw_os_error(),
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM | libc::EADDRNOTAVAIL)
        )
    }
    #[cfg(not(unix))]
    {
        let _ = err;
        false
    }
}

/// Which host limit an exhausted-resource error points at.
fn host_limit_hint(err: &io::Error) -> &'static str {
    #[cfg(unix)]
    {
        match err.raw_os_error() {
            Some(libc::EMFILE) => {
                "this process reached its open-file limit (raise ulimit -n, or LimitNOFILE for a service)"
            }
            Some(libc::ENFILE) => "the host reached its system-wide open-file limit",
            Some(libc::EADDRNOTAVAIL) => {
                "the host ran out of local ports for this destination (widen the ephemeral port range)"
            }
            _ => "the host is out of socket memory",
        }
    }
    #[cfg(not(unix))]
    {
        let _ = err;
        "the host is out of sockets"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_relay::RelayExitMode;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;

    /// Raise this test process's open-file limit (macOS starts at 256).
    fn raise_fd_limit() {
        #[cfg(unix)]
        // SAFETY: getrlimit/setrlimit on a local struct.
        unsafe {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
                limit.rlim_cur = limit.rlim_max.min(8192);
                libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
            }
        }
    }

    /// An echo server for any number of connections on one thread.
    fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let poller = Poller::new().unwrap();
            // SAFETY: the listener outlives the poller loop (never dropped).
            unsafe { poller.add(&listener, Event::readable(0)).unwrap() };
            let mut streams: HashMap<usize, TcpStream> = HashMap::new();
            let mut next = 1usize;
            let mut events = Events::new();
            let mut buffer = [0u8; 4096];
            loop {
                events.clear();
                poller.wait(&mut events, None).unwrap();
                for event in events.iter() {
                    if event.key == 0 {
                        while let Ok((stream, _)) = listener.accept() {
                            stream.set_nonblocking(true).unwrap();
                            // SAFETY: deleted before the stream drops below.
                            unsafe { poller.add(&stream, Event::readable(next)).unwrap() };
                            streams.insert(next, stream);
                            next += 1;
                        }
                        poller.modify(&listener, Event::readable(0)).unwrap();
                        continue;
                    }
                    let Some(mut stream) = streams.remove(&event.key) else {
                        continue;
                    };
                    match stream.read(&mut buffer) {
                        Ok(0) => {
                            let _ = poller.delete(&stream);
                        }
                        Ok(read) => {
                            let _ = stream.write_all(&buffer[..read]);
                            poller.modify(&stream, Event::readable(event.key)).unwrap();
                            streams.insert(event.key, stream);
                        }
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            poller.modify(&stream, Event::readable(event.key)).unwrap();
                            streams.insert(event.key, stream);
                        }
                        Err(_) => {
                            let _ = poller.delete(&stream);
                        }
                    }
                }
            }
        });
        address
    }

    struct TestFlow {
        to_proxy: SyncSender<Vec<u8>>,
        from_proxy: Receiver<Vec<u8>>,
        exit_state: RelayExitState,
        waker: RelayWaker,
    }

    impl TestFlow {
        /// What the poll loop does after draining the host->guest channel.
        fn drained(&self) {
            if self.exit_state_host_blocked() {
                self.waker.wake();
            }
        }

        fn exit_state_host_blocked(&self) -> bool {
            self.exit_state
                .host_blocked_flag()
                .swap(false, Ordering::AcqRel)
        }
    }

    fn start_reactor() -> (RelayReactor, Arc<WakePipe>) {
        let relay_wake = Arc::new(WakePipe::new());
        let reactor = RelayReactor::start(relay_wake.clone(), Arc::new(|| false)).unwrap();
        (reactor, relay_wake)
    }

    fn open_flow(
        reactor: &RelayReactor,
        id: u64,
        target: RelayTarget,
        destination: SocketAddr,
    ) -> TestFlow {
        let (to_proxy, from_smoltcp) = mpsc::sync_channel(32);
        let (to_smoltcp, from_proxy) = mpsc::sync_channel(32);
        let exit_state = RelayExitState::new();
        let waker = reactor.waker(id);
        reactor.adopt(NewTcpConnection {
            destination,
            relay_target: target,
            from_smoltcp,
            to_smoltcp,
            exit_state: exit_state.clone(),
            proxy_wake: waker.clone(),
            watch_opening: None,
        });
        TestFlow {
            to_proxy,
            from_proxy,
            exit_state,
            waker,
        }
    }

    fn send(flow: &TestFlow, payload: &[u8]) {
        flow.to_proxy.send(payload.to_vec()).unwrap();
        flow.waker.wake();
    }

    fn wait_for(flow: &TestFlow, mode: RelayExitMode) {
        let started = Instant::now();
        while flow.exit_state.load() != mode {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "flow is {:?}, expected {mode:?}",
                flow.exit_state.load()
            );
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// Descriptors of this process that are TCP sockets with `port` at
    /// either end. Other tests run in this process too, so a count of every
    /// descriptor would include theirs.
    #[cfg(target_os = "linux")]
    fn sockets_on_port(port: u16) -> usize {
        let wanted = format!(":{port:04X}");
        let mut inodes = std::collections::HashSet::new();
        for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
            for line in std::fs::read_to_string(table)
                .unwrap_or_default()
                .lines()
                .skip(1)
            {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() > 9
                    && (fields[1].ends_with(&wanted) || fields[2].ends_with(&wanted))
                {
                    inodes.insert(format!("socket:[{}]", fields[9]));
                }
            }
        }
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .flatten()
            .filter(|fd| {
                std::fs::read_link(fd.path())
                    .is_ok_and(|target| inodes.contains(target.to_string_lossy().as_ref()))
            })
            .count()
    }

    #[test]
    fn thousands_of_flows_share_one_thread_and_one_socket_each() {
        raise_fd_limit();
        let server = echo_server();
        let (reactor, _relay_wake) = start_reactor();
        let count = 2000;
        let flows: Vec<TestFlow> = (1..=count)
            .map(|id| open_flow(&reactor, id, RelayTarget::Connect(server), server))
            .collect();
        for (index, flow) in flows.iter().enumerate() {
            send(flow, &(index as u32).to_be_bytes());
        }
        for (index, flow) in flows.iter().enumerate() {
            let mut echoed = Vec::new();
            while echoed.len() < 4 {
                echoed.extend(
                    flow.from_proxy
                        .recv_timeout(Duration::from_secs(10))
                        .unwrap(),
                );
                flow.drained();
            }
            assert_eq!(echoed, (index as u32).to_be_bytes());
        }
        // Each flow holds its relay socket and the server's accepted end, and
        // nothing more: no per-flow poller, wake pipe or thread.
        #[cfg(target_os = "linux")]
        {
            let sockets = sockets_on_port(server.port());
            assert!(
                sockets <= 2 * count as usize + 1,
                "{sockets} sockets on the server's port for {count} flows"
            );
        }
        for flow in &flows {
            assert_eq!(flow.exit_state.load(), RelayExitMode::Running);
        }
    }

    #[test]
    fn a_full_host_to_guest_channel_resumes_once_drained() {
        // A server that sends far more than the channel holds as soon as it
        // accepts, before the guest reads anything.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server = listener.local_addr().unwrap();
        let total = 4 * 1024 * 1024;
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let block = vec![7u8; 64 * 1024];
            let mut sent = 0;
            while sent < total {
                stream.write_all(&block).unwrap();
                sent += block.len();
            }
        });
        let (reactor, _relay_wake) = start_reactor();
        let flow = open_flow(&reactor, 1, RelayTarget::Connect(server), server);
        // Let the relay fill the channel and park on it.
        thread::sleep(Duration::from_millis(200));
        let mut received = 0;
        while received < total {
            let payload = flow
                .from_proxy
                .recv_timeout(Duration::from_secs(5))
                .expect("the relay resumes after the channel drains");
            received += payload.len();
            flow.drained();
        }
        assert_eq!(received, total);
    }

    #[test]
    fn a_guest_close_ends_the_flow_and_frees_its_socket() {
        let server = echo_server();
        let (reactor, _relay_wake) = start_reactor();
        let flow = open_flow(&reactor, 1, RelayTarget::Connect(server), server);
        send(&flow, b"hi");
        assert_eq!(
            flow.from_proxy
                .recv_timeout(Duration::from_secs(5))
                .unwrap(),
            b"hi"
        );
        let TestFlow {
            to_proxy,
            exit_state,
            waker,
            from_proxy,
        } = flow;
        drop(to_proxy);
        waker.wake();
        let flow = TestFlow {
            to_proxy: mpsc::sync_channel(1).0,
            from_proxy,
            exit_state,
            waker,
        };
        // The relay half-closes toward the server, the server closes, and the
        // flow ends cleanly.
        wait_for(&flow, RelayExitMode::Graceful);
    }

    #[test]
    fn a_flow_whose_guest_is_gone_ends_even_if_the_remote_never_closes() {
        // A remote that accepts and then never reads, writes or closes.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server = listener.local_addr().unwrap();
        let (held_tx, held_rx) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            held_tx.send(stream).unwrap();
            thread::sleep(Duration::from_secs(30));
        });
        let (reactor, _relay_wake) = start_reactor();
        let flow = open_flow(&reactor, 1, RelayTarget::Connect(server), server);
        let _held = held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let TestFlow {
            to_proxy,
            from_proxy,
            exit_state,
            waker,
        } = flow;
        // The poll loop drops the flow's entry: guest side closed for good.
        exit_state.mark_guest_gone();
        drop(to_proxy);
        waker.wake();
        let flow = TestFlow {
            to_proxy: mpsc::sync_channel(1).0,
            from_proxy,
            exit_state,
            waker,
        };
        wait_for(&flow, RelayExitMode::Graceful);
    }

    #[test]
    fn an_intercepted_flow_opens_off_the_reactor_then_relays() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let endpoint = crate::InterceptEndpoint {
            addr: listener.local_addr().unwrap(),
            token: [0x5a; smolvm_protocol::intercept::TOKEN_LEN],
        };
        let destination = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443);
        let interceptor = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let announced = endpoint.read_preamble(&mut stream).unwrap();
            stream
                .write_all(&[smolvm_protocol::intercept::VERDICT_CONNECTED])
                .unwrap();
            let mut buf = [0u8; 64];
            let read = stream.read(&mut buf).unwrap();
            stream.write_all(b"ack").unwrap();
            (announced, buf[..read].to_vec())
        });
        let (reactor, _relay_wake) = start_reactor();
        let flow = open_flow(
            &reactor,
            1,
            RelayTarget::Intercept {
                endpoint,
                destination,
            },
            destination,
        );
        send(&flow, b"\x16\x03\x01hello");
        assert_eq!(
            flow.from_proxy
                .recv_timeout(Duration::from_secs(5))
                .unwrap(),
            b"ack"
        );
        let (announced, first_bytes) = interceptor.join().unwrap();
        assert_eq!(announced, destination);
        assert_eq!(first_bytes, b"\x16\x03\x01hello");
    }

    #[test]
    fn a_host_that_answers_and_closes_at_once_never_resets_the_guest() {
        // Like an HTTP server answering `Connection: close`: it reads the
        // request, writes the whole response and closes, so its FIN arrives
        // on the same readable event as (or right after) the last bytes.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server = listener.local_addr().unwrap();
        let response = vec![b'r'; 3000];
        let served = response.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let served = served.clone();
                thread::spawn(move || {
                    let mut request = [0u8; 64];
                    let _ = stream.read(&mut request);
                    let _ = stream.write_all(&served);
                });
            }
        });
        let (reactor, _relay_wake) = start_reactor();
        for id in 1..=300u64 {
            let flow = open_flow(&reactor, id, RelayTarget::Connect(server), server);
            send(&flow, b"GET / HTTP/1.1\r\n\r\n");
            let mut received = Vec::new();
            while received.len() < response.len() {
                match flow.from_proxy.recv_timeout(Duration::from_secs(5)) {
                    Ok(payload) => received.extend(payload),
                    Err(_) => panic!(
                        "flow {id} got {} of {} bytes, then {:?}",
                        received.len(),
                        response.len(),
                        flow.exit_state.load()
                    ),
                }
                flow.drained();
            }
            assert_eq!(received, response, "flow {id}");
            // The host's FIN reaches the guest as a half-close, not a reset.
            wait_for(&flow, RelayExitMode::HalfClosed);
            thread::sleep(Duration::from_millis(1));
            assert_eq!(
                flow.exit_state.load(),
                RelayExitMode::HalfClosed,
                "flow {id}"
            );
        }
    }

    #[test]
    fn a_refused_connect_aborts_the_flow() {
        let closed = {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            listener.local_addr().unwrap()
        };
        let (reactor, relay_wake) = start_reactor();
        let flow = open_flow(&reactor, 1, RelayTarget::Connect(closed), closed);
        wait_for(&flow, RelayExitMode::Abort);
        drop(relay_wake);
    }

    #[test]
    fn a_published_connection_relays_both_ways() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let (reactor, _relay_wake) = start_reactor();
        let flow = open_flow(&reactor, 1, RelayTarget::Attached(accepted), address);
        client.write_all(b"ping").unwrap();
        assert_eq!(
            flow.from_proxy
                .recv_timeout(Duration::from_secs(5))
                .unwrap(),
            b"ping"
        );
        send(&flow, b"pong");
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"pong");
    }
}
