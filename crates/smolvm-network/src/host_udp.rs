/// Permit a complete UDP datagram on every host. macOS's default send buffer
/// is smaller than the maximum payload and otherwise returns EMSGSIZE.
pub(crate) fn configure(socket: &socket2::Socket) -> std::io::Result<()> {
    const MIN_BUFFER: usize = 128 * 1024;
    if socket.send_buffer_size()? < MIN_BUFFER {
        socket.set_send_buffer_size(MIN_BUFFER)?;
    }
    if socket.recv_buffer_size()? < MIN_BUFFER {
        socket.set_recv_buffer_size(MIN_BUFFER)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn peer() -> std::net::UdpSocket {
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let socket = socket2::SockRef::from(&peer);
    socket.set_send_buffer_size(128 * 1024).unwrap();
    socket.set_recv_buffer_size(128 * 1024).unwrap();
    peer
}

#[cfg(test)]
pub(crate) fn assert_maximum_datagram_round_trip(
    socket: std::net::UdpSocket,
    peer: std::net::UdpSocket,
) {
    use std::time::Duration;
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let payload = vec![37; 65507];
    if socket.peer_addr().is_ok() {
        socket.send(&payload).unwrap();
    } else {
        socket
            .send_to(&payload, peer.local_addr().unwrap())
            .unwrap();
    }
    let mut received = vec![0; 65535];
    let (n, source) = peer.recv_from(&mut received).unwrap();
    assert_eq!(&received[..n], payload);
    peer.send_to(&payload, source).unwrap();
    let (n, _) = socket.recv_from(&mut received).unwrap();
    assert_eq!(&received[..n], payload);
}
