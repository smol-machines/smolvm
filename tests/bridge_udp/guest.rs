use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    thread,
    time::Duration,
};
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
