use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    os::fd::AsRawFd,
    thread,
    time::Duration,
};
unsafe extern "C" {
    fn connect(fd: i32, address: *const u8, length: u32) -> i32;
}

fn udp_connected(first: std::net::SocketAddr, second: std::net::SocketAddr) {
    let local = if first.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(local).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket.connect(first).unwrap();
    let bound = socket.local_addr().unwrap();
    let mut received = [0; 65535];
    for size in [0, 1, 4096, 65507] {
        let data = vec![71; size];
        socket.send(&data).unwrap();
        let (length, peer) = socket.recv_from(&mut received).unwrap();
        assert_eq!(peer, first);
        assert_eq!(&received[..length], data.as_slice());
    }
    socket.send_to(b"alternate", second).unwrap();
    socket.send(b"connected").unwrap();
    let (length, peer) = socket.recv_from(&mut received).unwrap();
    assert_eq!(peer, first);
    assert_eq!(&received[..length], b"connected");
    assert_eq!(socket.peer_addr().unwrap(), first);
    assert_eq!(socket.local_addr().unwrap(), bound);
    let address = [0u8; 2];
    assert_eq!(
        unsafe { connect(socket.as_raw_fd(), address.as_ptr(), 2) },
        0
    );
    assert_eq!(socket.peer_addr().unwrap_err().raw_os_error(), Some(107));
    assert_eq!(socket.local_addr().unwrap(), local.parse().unwrap());
    socket.send_to(b"disconnected", second).unwrap();
    let (length, peer) = socket.recv_from(&mut received).unwrap();
    assert_eq!(peer, second);
    assert_eq!(&received[..length], b"disconnected");
    socket.connect(first).unwrap();
    socket.send(b"reconnected").unwrap();
    let (length, peer) = socket.recv_from(&mut received).unwrap();
    assert_eq!(peer, first);
    assert_eq!(&received[..length], b"reconnected");
    println!("UDP_CONNECTED_PASS");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args[1].as_str() {
        "serve" => {
            let ip: std::net::IpAddr = args[2].parse().unwrap();
            let tcp = TcpListener::bind((
                ip,
                args.get(3).map(|p| p.parse::<u16>().unwrap()).unwrap_or(0),
            ))
            .unwrap();
            let udp = UdpSocket::bind((
                ip,
                args.get(4).map(|p| p.parse::<u16>().unwrap()).unwrap_or(0),
            ))
            .unwrap();
            println!(
                "READY {} {}",
                tcp.local_addr().unwrap(),
                udp.local_addr().unwrap()
            );
            thread::spawn(move || {
                for connection in tcp.incoming() {
                    let mut stream = connection.unwrap();
                    let mut data = [0; 4];
                    stream.read_exact(&mut data).unwrap();
                    assert_eq!(&data, b"PING");
                    stream.write_all(b"PONG").unwrap();
                }
            });
            let mut data = [0; 65535];
            loop {
                let (n, peer) = udp.recv_from(&mut data).unwrap();
                udp.send_to(&data[..n], peer).unwrap();
            }
        }
        "tcp" => {
            let mut stream = TcpStream::connect(&args[2]).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream.write_all(b"PING").unwrap();
            let mut data = [0; 4];
            stream.read_exact(&mut data).unwrap();
            assert_eq!(&data, b"PONG");
            println!("TCP_PASS");
        }
        "udp" => {
            let peer: std::net::SocketAddr = args[2].parse().unwrap();
            let socket = UdpSocket::bind(if peer.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            for size in [0, 1, 4096, 65507] {
                let data = vec![71; size];
                socket.send_to(&data, peer).unwrap();
                let mut received = [0; 65535];
                let (n, source) = socket.recv_from(&mut received).unwrap();
                assert_eq!(source, peer);
                assert_eq!(&received[..n], data.as_slice());
            }
            println!("UDP_PASS");
        }
        "socket-options" => {
            let stream = TcpStream::connect(&args[2]).unwrap();
            for enabled in [true, false] {
                stream.set_nodelay(enabled).unwrap();
                assert_eq!(stream.nodelay().unwrap(), enabled);
            }
            let mut stream = stream;
            stream.write_all(b"PING").unwrap();
            let mut reply = [0; 4];
            stream.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"PONG");
            let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
            socket.connect(&args[3]).unwrap();
            socket.set_ttl(37).unwrap();
            assert_eq!(socket.ttl().unwrap(), 37);
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket.send(b"PING").unwrap();
            assert_eq!(socket.recv(&mut reply).unwrap(), 4);
            assert_eq!(&reply, b"PING");
            println!("SOCKET_OPTIONS_PASS");
        }
        "udp-connected" => udp_connected(args[2].parse().unwrap(), args[3].parse().unwrap()),
        "udp-error" => {
            let peer: std::net::SocketAddr = args[2].parse().unwrap();
            let socket = UdpSocket::bind(if peer.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket.connect(peer).unwrap();
            socket.send(b"closed-port").unwrap();
            assert_eq!(
                socket.recv(&mut [0; 8]).unwrap_err().raw_os_error(),
                Some(111)
            );
            assert!(socket.take_error().unwrap().is_none());
            socket.set_nonblocking(true).unwrap();
            assert_eq!(
                socket.recv(&mut [0; 8]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            println!("UDP_ERROR_PASS");
        }
        "bind" => match TcpListener::bind(&args[2]) {
            Ok(_socket) => println!("BIND_PASS"),
            Err(error) => {
                eprintln!("BIND_ERR={:?}", error.raw_os_error());
                std::process::exit(9);
            }
        },
        "write" => {
            fs::write("/persisted", b"host-network-preserves-data").unwrap();
            println!("WRITE_PASS");
        }
        "read" => {
            assert_eq!(
                fs::read("/persisted").unwrap(),
                b"host-network-preserves-data"
            );
            println!("READ_PASS");
        }
        "true" => println!("PASS"),
        _ => panic!("unknown probe"),
    }
}
