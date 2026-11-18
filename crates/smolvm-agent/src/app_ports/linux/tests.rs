use super::*;

fn row(ip: &str, port: u16, inode: u64, state: &str) -> String {
    format!("0: {ip}:{port:04X} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000 0 0 {inode} 1\n")
}
fn ipv4(ip: Ipv4Addr) -> String {
    format!("{:08X}", u32::from_ne_bytes(ip.octets()))
}
fn ipv6(ip: Ipv6Addr) -> String {
    ip.octets()
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| format!("{:08X}", u32::from_ne_bytes(*c)))
        .collect()
}

#[test]
fn reads_only_listening_tcp_sockets_with_native_proc_address_encoding() {
    let input = format!(
        "header\n{}{}",
        row(&ipv4(Ipv4Addr::LOCALHOST), 3000, 81, "0A"),
        row(&ipv4(Ipv4Addr::LOCALHOST), 9000, 82, "01")
    );
    assert_eq!(
        parse(&input, false).unwrap(),
        vec![Listener {
            address: "127.0.0.1:3000".parse().unwrap(),
            inode: 81
        }]
    );
    assert_eq!(
        parse(
            &format!(
                "header\n{}",
                row(&ipv6(Ipv6Addr::LOCALHOST), 8080, 92, "0A")
            ),
            true
        )
        .unwrap()[0]
            .address,
        "[::1]:8080".parse().unwrap()
    );
    for invalid in ["header\nmalformed", "header\n0: broken x 0A 0 0 0 0 0 1"] {
        assert!(parse(invalid, false).is_err());
    }
}

#[cfg(unix)]
#[test]
fn excludes_sibling_processes_and_shared_reuseport_endpoints_and_rejects_stale_owner() {
    let root = tempfile::tempdir().unwrap();
    let proc = root.path().join("proc");
    let cgroup = root.path().join("group");
    fs::create_dir_all(proc.join("42/fd")).unwrap();
    fs::create_dir_all(proc.join("42/net")).unwrap();
    fs::create_dir_all(proc.join("43/fd")).unwrap();
    fs::create_dir_all(&cgroup).unwrap();
    fs::write(cgroup.join("cgroup.procs"), "42\n").unwrap();
    fs::create_dir(cgroup.join("workers")).unwrap();
    fs::write(cgroup.join("workers/cgroup.procs"), "43\n").unwrap();
    // A nested worker belongs to the workload, but a symlink to a different
    // cgroup must never extend the ownership boundary.
    let outside = root.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("cgroup.procs"), "99\n").unwrap();
    std::os::unix::fs::symlink(outside, cgroup.join("escape")).unwrap();
    std::os::unix::fs::symlink("socket:[1]", proc.join("42/fd/3")).unwrap();
    std::os::unix::fs::symlink("socket:[2]", proc.join("43/fd/4")).unwrap();
    std::os::unix::fs::symlink("socket:[3]", proc.join("43/fd/5")).unwrap();
    let table = format!(
        "header\n{}{}{}{}{}",
        row(&ipv4(Ipv4Addr::LOCALHOST), 3000, 1, "0A"),
        row(&ipv4(Ipv4Addr::LOCALHOST), 8080, 2, "0A"),
        row(&ipv4(Ipv4Addr::LOCALHOST), 9000, 3, "0A"),
        row(&ipv4(Ipv4Addr::LOCALHOST), 9000, 4, "0A"),
        row(&ipv4(Ipv4Addr::LOCALHOST), 5432, 5, "0A")
    );
    fs::write(proc.join("42/net/tcp"), table).unwrap();
    let workload = Workload {
        proc,
        cgroup,
        pid: 42,
    };
    assert_eq!(
        workload
            .listeners()
            .unwrap()
            .iter()
            .map(|l| l.address.port())
            .collect::<Vec<_>>(),
        vec![3000, 8080]
    );
    fs::write(workload.cgroup.join("cgroup.procs"), "43\n").unwrap();
    assert!(workload.listeners().is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn discovers_and_connects_a_real_owned_socket_without_expose_or_published_ports() {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let group = tempfile::tempdir().unwrap();
    let pid = std::process::id();
    fs::write(group.path().join("cgroup.procs"), format!("{pid}\n")).unwrap();
    let workload = Workload {
        proc: "/proc".into(),
        cgroup: group.path().into(),
        pid,
    };
    assert!(workload
        .listeners()
        .unwrap()
        .iter()
        .any(|l| l.address.port() == port));
    let mut stream = workload.connect(port).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(b"private app bytes").unwrap();
    let mut received = [0; 17];
    server.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"private app bytes");
    drop(listener);
    assert!(workload.connect(port).is_err());
}
