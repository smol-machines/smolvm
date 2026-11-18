use std::cell::RefCell;
use std::collections::BinaryHeap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::Mutex;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::Tracer;
use smoltcp::phy::{self, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};

const MAC_A: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([2, 0, 0, 0, 0, 1]));
const MAC_B: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([2, 0, 0, 0, 0, 2]));
const IP_A: IpAddress = IpAddress::v4(10, 0, 0, 1);
const IP_B: IpAddress = IpAddress::v4(10, 0, 0, 2);

const BYTES: usize = 10 * 1024 * 1024;

static CLOCK: Mutex<(Instant, char)> = Mutex::new((Instant::ZERO, ' '));

#[test]
fn netsim() {
    setup_logging();

    let buffers = [128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768];
    let losses = [0.0, 0.001, 0.01, 0.02, 0.05, 0.10, 0.20, 0.30];

    let mut s = String::new();

    write!(&mut s, "buf\\loss").unwrap();
    for loss in losses {
        write!(&mut s, "{loss:9.3} ").unwrap();
    }
    writeln!(&mut s).unwrap();

    for buffer in buffers {
        write!(&mut s, "{buffer:7}").unwrap();
        for loss in losses {
            let r = run_test(TestCase {
                rtt: Duration::from_millis(100),
                buffer,
                loss,
            });
            write!(&mut s, " {r:9.2}").unwrap();
        }
        writeln!(&mut s).unwrap();
    }

    insta::assert_snapshot!(s);
}

struct TestCase {
    rtt: Duration,
    loss: f64,
    buffer: usize,
}

fn run_test(case: TestCase) -> f64 {
    let mut time = Instant::ZERO;

    let params = QueueParams {
        latency: case.rtt / 2,
        loss: case.loss,
    };
    let queue_a_to_b = RefCell::new(PacketQueue::new(params.clone(), 0));
    let queue_b_to_a = RefCell::new(PacketQueue::new(params.clone(), 1));
    let device_a = QueueDevice::new(&queue_a_to_b, &queue_b_to_a, Medium::Ethernet);
    let device_b = QueueDevice::new(&queue_b_to_a, &queue_a_to_b, Medium::Ethernet);

    let mut device_a = Tracer::new(device_a, |_timestamp, _printer| log::trace!("{}", _printer));
    let mut device_b = Tracer::new(device_b, |_timestamp, _printer| log::trace!("{}", _printer));

    let mut iface_a = Interface::new(Config::new(MAC_A), &mut device_a, time);
    iface_a.update_ip_addrs(|a| a.push(IpCidr::new(IP_A, 8)).unwrap());
    let mut iface_b = Interface::new(Config::new(MAC_B), &mut device_b, time);
    iface_b.update_ip_addrs(|a| a.push(IpCidr::new(IP_B, 8)).unwrap());

    // Create sockets
    let socket_a = {
        let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; case.buffer]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; case.buffer]);
        tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer)
    };

    let socket_b = {
        let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; case.buffer]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; case.buffer]);
        tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer)
    };

    let mut sockets_a: [_; 2] = Default::default();
    let mut sockets_a = SocketSet::new(&mut sockets_a[..]);
    let socket_a_handle = sockets_a.add(socket_a);

    let mut sockets_b: [_; 2] = Default::default();
    let mut sockets_b = SocketSet::new(&mut sockets_b[..]);
    let socket_b_handle = sockets_b.add(socket_b);

    let mut did_listen = false;
    let mut did_connect = false;
    let mut processed = 0;
    while processed < BYTES {
        *CLOCK.lock().unwrap() = (time, ' ');
        log::info!("loop");
        //println!("t = {}", time);

        *CLOCK.lock().unwrap() = (time, 'A');

        iface_a.poll(time, &mut device_a, &mut sockets_a);

        let socket = sockets_a.get_mut::<tcp::Socket>(socket_a_handle);
        if !socket.is_active() && !socket.is_listening() && !did_listen {
            //println!("listening");
            socket.listen(1234).unwrap();
            did_listen = true;
        }

        while socket.can_recv() {
            let received = socket.recv(|buffer| (buffer.len(), buffer.len())).unwrap();
            //println!("got {:?}", received,);
            processed += received;
        }

        *CLOCK.lock().unwrap() = (time, 'B');
        iface_b.poll(time, &mut device_b, &mut sockets_b);
        let socket = sockets_b.get_mut::<tcp::Socket>(socket_b_handle);
        let cx = iface_b.context();
        if !socket.is_open() && !did_connect {
            //println!("connecting");
            socket.connect(cx, (IP_A, 1234), 65000).unwrap();
            did_connect = true;
        }

        while socket.can_send() {
            //println!("sending");
            socket.send(|buffer| (buffer.len(), ())).unwrap();
        }

        *CLOCK.lock().unwrap() = (time, ' ');

        let mut next_time = queue_a_to_b.borrow_mut().next_expiration();
        next_time = next_time.min(queue_b_to_a.borrow_mut().next_expiration());
        if let Some(t) = iface_a.poll_at(time, &sockets_a) {
            next_time = next_time.min(t);
        }
        if let Some(t) = iface_b.poll_at(time, &sockets_b) {
            next_time = next_time.min(t);
        }
        assert!(next_time.total_micros() != i64::MAX);
        time = time.max(next_time);
    }

    let duration = time - Instant::ZERO;
    processed as f64 / duration.total_micros() as f64 * 1e6
}

struct Packet {
    timestamp: Instant,
    id: u64,
    data: Vec<u8>,
}

impl PartialEq for Packet {
    fn eq(&self, other: &Self) -> bool {
        (other.timestamp, other.id) == (self.timestamp, self.id)
    }
}

impl Eq for Packet {}

impl PartialOrd for Packet {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Packet {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (other.timestamp, other.id).cmp(&(self.timestamp, self.id))
    }
}

#[derive(Clone)]
struct QueueParams {
    latency: Duration,
    loss: f64,
}

struct PacketQueue {
    queue: BinaryHeap<Packet>,
    next_id: u64,
    params: QueueParams,
    rng: ChaCha20Rng,
}

impl PacketQueue {
    pub fn new(params: QueueParams, seed: u64) -> Self {
        Self {
            queue: BinaryHeap::new(),
            next_id: 0,
            params,
            rng: ChaCha20Rng::seed_from_u64(seed),
        }
    }

    pub fn next_expiration(&self) -> Instant {
        self.queue
            .peek()
            .map(|p| p.timestamp)
            .unwrap_or(Instant::from_micros(i64::MAX))
    }

    pub fn push(&mut self, data: Vec<u8>, timestamp: Instant) {
        if self.rng.r#gen::<f64>() < self.params.loss {
            log::info!("PACKET LOST!");
            return;
        }

        self.queue.push(Packet {
            data,
            id: self.next_id,
            timestamp: timestamp + self.params.latency,
        });
        self.next_id += 1;
    }

    pub fn pop(&mut self, timestamp: Instant) -> Option<Vec<u8>> {
        let p = self.queue.peek()?;
        if p.timestamp > timestamp {
            return None;
        }
        Some(self.queue.pop().unwrap().data)
    }
}

pub struct QueueDevice<'a> {
    tx_queue: &'a RefCell<PacketQueue>,
    rx_queue: &'a RefCell<PacketQueue>,
    medium: Medium,
}

impl<'a> QueueDevice<'a> {
    fn new(
        tx_queue: &'a RefCell<PacketQueue>,
        rx_queue: &'a RefCell<PacketQueue>,
        medium: Medium,
    ) -> Self {
        Self {
            tx_queue,
            rx_queue,
            medium,
        }
    }
}

impl Device for QueueDevice<'_> {
    type RxToken<'a>
        = RxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a>
    where
        Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1514;
        caps.medium = self.medium;
        caps.checksum = ChecksumCapabilities::ignored();
        caps
    }

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_queue
            .borrow_mut()
            .pop(timestamp)
            .map(move |buffer| {
                let rx = RxToken { buffer };
                let tx = TxToken {
                    queue: self.tx_queue,
                    timestamp,
                };
                (rx, tx)
            })
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            queue: self.tx_queue,
            timestamp,
        })
    }
}

pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

pub struct TxToken<'a> {
    queue: &'a RefCell<PacketQueue>,
    timestamp: Instant,
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.queue.borrow_mut().push(buffer, self.timestamp);
        result
    }
}

pub fn setup_logging() {
    env_logger::Builder::new()
        .format(move |buf, record| {
            let (elapsed, side) = *CLOCK.lock().unwrap();

            let timestamp = format!("[{elapsed} {side}]");
            if record.target().starts_with("smoltcp::") {
                writeln!(
                    buf,
                    "{} ({}): {}",
                    timestamp,
                    record.target().replace("smoltcp::", ""),
                    record.args()
                )
            } else if record.level() == log::Level::Trace {
                let message = format!("{}", record.args());
                writeln!(
                    buf,
                    "{} {}",
                    timestamp,
                    message.replace('\n', "\n             ")
                )
            } else {
                writeln!(
                    buf,
                    "{} ({}): {}",
                    timestamp,
                    record.target(),
                    record.args()
                )
            }
        })
        .parse_env("RUST_LOG")
        .init();
}
