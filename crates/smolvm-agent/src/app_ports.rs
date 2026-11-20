//! On-demand app access over the existing agent connection. No watcher, shell,
//! host port publication, or extra guest listener is needed.
use smolvm_protocol::{error_codes, AgentResponse};

pub(crate) fn list(overlay: &str) -> AgentResponse {
    #[cfg(target_os = "linux")]
    {
        match linux::workload(overlay).and_then(|workload| workload.listeners()) {
            Ok(listeners) => AgentResponse::Ok {
                data: Some(
                    serde_json::json!({"ports": listeners.into_iter().map(|l| l.address.port()).collect::<std::collections::BTreeSet<_>>(), "listener_notifications": crate::listener_watch::supported()}),
                ),
            },
            Err(error) => AgentResponse::error(
                format!("app ports unavailable: {error}"),
                error_codes::QUERY_FAILED,
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = overlay;
        AgentResponse::error("app ports require Linux", error_codes::INVALID_REQUEST)
    }
}

pub(crate) fn connect(
    stream: &mut crate::WireStream<impl crate::ReadWrite>,
    overlay: &str,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        // App streams must not consume the 32 ordinary work slots. Limit them
        // separately, leaving room in the 64 connection slots for control.
        static ACTIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        struct Slot;
        impl Drop for Slot {
            fn drop(&mut self) {
                ACTIVE.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
        }
        if ACTIVE.fetch_add(1, std::sync::atomic::Ordering::AcqRel) >= 16 {
            ACTIVE.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            crate::send_response(
                stream,
                &AgentResponse::error("too many active app connections", error_codes::QUERY_FAILED),
            )?;
            return Ok(());
        }
        let _slot = Slot;
        let target = linux::workload(overlay).and_then(|workload| workload.connect(port));
        match target {
            Ok(peer) => {
                crate::send_response(
                    stream,
                    &AgentResponse::Ok {
                        data: Some(serde_json::json!({"protocol":"smol-app-tcp-v1"})),
                    },
                )?;
                crate::relay::relay_half_close(crate::WireStream::new(stream), peer)?;
            }
            Err(error) => crate::send_response(
                stream,
                &AgentResponse::error(
                    format!("app connection unavailable: {error}"),
                    error_codes::QUERY_FAILED,
                ),
            )?,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (overlay, port);
        crate::send_response(
            stream,
            &AgentResponse::error(
                "app connections require Linux",
                error_codes::INVALID_REQUEST,
            ),
        )?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
mod linux {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        io::{self, Read},
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        path::{Path, PathBuf},
    };
    #[cfg(target_os = "linux")]
    use std::{net::TcpStream, time::Duration};
    const MAX_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_PIDS: usize = 4096;
    const MAX_FDS: usize = 65536;
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(super) struct Listener {
        pub address: SocketAddr,
        inode: u64,
    }
    pub(super) struct Workload {
        proc: PathBuf,
        cgroup: PathBuf,
        pid: u32,
    }

    #[cfg(target_os = "linux")]
    pub(super) fn workload(overlay: &str) -> io::Result<Workload> {
        let id = crate::resolve_main_container(Some(overlay))
            .ok_or_else(|| invalid("container is not running"))?;
        if id.is_empty()
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(invalid("invalid runtime container"));
        }
        let pid =
            crate::crun_container_pid(&id).ok_or_else(|| invalid("container is not running"))?;
        Ok(Workload {
            proc: "/proc".into(),
            cgroup: Path::new("/sys/fs/cgroup/smolvm/docker").join(id),
            pid,
        })
    }
    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }
    fn read(path: &Path) -> io::Result<String> {
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(invalid("app metadata exceeds limit"));
        }
        String::from_utf8(bytes).map_err(|_| invalid("invalid app metadata"))
    }
    impl Workload {
        fn pids(&self) -> io::Result<BTreeSet<u32>> {
            let mut pids = BTreeSet::new();
            let mut pending = vec![self.cgroup.clone()];
            let mut groups = 0;
            while let Some(group) = pending.pop() {
                groups += 1;
                if groups > MAX_PIDS {
                    return Err(invalid("too many container process groups"));
                }
                let text = match read(&group.join("cgroup.procs")) {
                    Ok(text) => text,
                    Err(error)
                        if group != self.cgroup && error.kind() == io::ErrorKind::NotFound =>
                    {
                        continue
                    }
                    Err(error) => return Err(error),
                };
                for pid in text.split_whitespace() {
                    pids.insert(
                        pid.parse::<u32>()
                            .map_err(|_| invalid("invalid process identity"))?,
                    );
                    if pids.len() > MAX_PIDS {
                        return Err(invalid("too many container processes"));
                    }
                }
                for entry in fs::read_dir(group)? {
                    let entry = entry?;
                    if entry.file_type()?.is_dir() {
                        if groups + pending.len() >= MAX_PIDS {
                            return Err(invalid("too many container process groups"));
                        }
                        pending.push(entry.path());
                    }
                }
            }
            if pids.len() > MAX_PIDS || !pids.contains(&self.pid) {
                return Err(invalid("container ownership changed"));
            }
            Ok(pids)
        }
        pub(super) fn listeners(&self) -> io::Result<Vec<Listener>> {
            let pids = self.pids()?;
            let mut owned = BTreeSet::new();
            #[cfg(target_os = "linux")]
            let mut descriptors = Vec::new();
            let mut fds = 0;
            for &pid in &pids {
                let entries = match fs::read_dir(self.proc.join(pid.to_string()).join("fd")) {
                    Ok(entries) => entries,
                    Err(e) if e.kind() == io::ErrorKind::NotFound && pid != self.pid => continue,
                    Err(e) => return Err(e),
                };
                for entry in entries {
                    fds += 1;
                    if fds > MAX_FDS {
                        return Err(invalid("app descriptors exceed limit"));
                    }
                    let entry = entry?;
                    let link = match fs::read_link(entry.path()) {
                        Ok(link) => link,
                        Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                        Err(e) => return Err(e),
                    };
                    if let Some(inode) = link
                        .to_str()
                        .and_then(|s| s.strip_prefix("socket:["))
                        .and_then(|s| s.strip_suffix(']'))
                        .and_then(|s| s.parse::<u64>().ok())
                    {
                        owned.insert(inode);
                        #[cfg(target_os = "linux")]
                        if let Some(fd) = entry
                            .file_name()
                            .to_str()
                            .and_then(|s| s.parse::<i32>().ok())
                        {
                            descriptors.push((pid, fd, inode));
                        }
                    }
                }
            }
            let mut listeners = Vec::new();
            for (file, ipv6) in [("tcp", false), ("tcp6", true)] {
                match read(&self.proc.join(self.pid.to_string()).join("net").join(file)) {
                    Ok(text) => listeners.extend(parse(&text, ipv6)?),
                    Err(e) if ipv6 && e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
            // SO_REUSEPORT can put unrelated workloads on the same endpoint.
            // Do not advertise an endpoint that could reach somebody else.
            let mut exclusive = BTreeMap::new();
            #[cfg(target_os = "linux")]
            let native: BTreeSet<_> = listeners.iter().map(|l| l.inode).collect();
            for listener in &listeners {
                *exclusive.entry(listener.address).or_insert(true) &=
                    owned.contains(&listener.inode);
            }
            listeners.retain(|l| owned.contains(&l.inode) && exclusive[&l.address]);
            #[cfg(target_os = "linux")]
            {
                // TSI sockets have their own kernel family and never appear
                // in /proc/net/tcp. Inspect only owned descriptors absent from
                // that table; ordinary TCP discovery retains its reuse-port
                // ownership check above.
                let mut processes = BTreeMap::new();
                for (pid, fd, inode) in descriptors {
                    if native.contains(&inode) {
                        continue;
                    }
                    if let std::collections::btree_map::Entry::Vacant(entry) = processes.entry(pid)
                    {
                        match descriptor::process(pid) {
                            Ok(process) => {
                                entry.insert(process);
                            }
                            Err(error)
                                if error.raw_os_error() == Some(libc::ESRCH) && pid != self.pid =>
                            {
                                continue
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    if let Some(listener) = descriptor::tsi_listener(&processes[&pid], fd, inode)? {
                        listeners.push(listener);
                    }
                }
            }
            if self.pids()? != pids {
                return Err(invalid("container ownership changed during discovery"));
            }
            listeners.sort_by_key(|l| (!l.address.ip().is_loopback(), l.address));
            listeners.dedup();
            if listeners.len() > 4096 {
                return Err(invalid("too many app listeners"));
            }
            Ok(listeners)
        }
        #[cfg(target_os = "linux")]
        pub(super) fn connect(&self, port: u16) -> io::Result<TcpStream> {
            if port == 0 {
                return Err(invalid("invalid app port"));
            }
            for listener in self
                .listeners()?
                .into_iter()
                .filter(|l| l.address.port() == port)
            {
                let address = match listener.address.ip() {
                    IpAddr::V4(ip) if ip.is_unspecified() => {
                        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
                    }
                    IpAddr::V6(ip) if ip.is_unspecified() => {
                        SocketAddr::from((Ipv6Addr::LOCALHOST, port))
                    }
                    _ => listener.address,
                };
                if let Ok(stream) = TcpStream::connect_timeout(&address, Duration::from_secs(2)) {
                    // Pin the listening inode on both sides of connect. A
                    // stopped/replaced workload must not redirect the stream.
                    if !self.listeners()?.contains(&listener) {
                        return Err(invalid("app ownership changed during connect"));
                    }
                    stream.set_nodelay(true)?;
                    return Ok(stream);
                }
            }
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "no owned app listener accepted the connection",
            ))
        }
    }
    fn parse(text: &str, ipv6: bool) -> io::Result<Vec<Listener>> {
        let mut result = Vec::new();
        for line in text.lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 10 {
                return Err(invalid("invalid TCP listener inventory"));
            }
            if fields[3] != "0A" {
                continue;
            }
            let (ip, port) = fields[1]
                .split_once(':')
                .ok_or_else(|| invalid("invalid TCP address"))?;
            let port = u16::from_str_radix(port, 16).map_err(|_| invalid("invalid TCP port"))?;
            let inode = fields[9]
                .parse::<u64>()
                .map_err(|_| invalid("invalid socket identity"))?;
            if port == 0 || inode == 0 || ip.len() != if ipv6 { 32 } else { 8 } {
                return Err(invalid("invalid TCP listener"));
            }
            let mut octets = Vec::new();
            for chunk in ip.as_bytes().as_chunks::<8>().0 {
                let hex = std::str::from_utf8(chunk).map_err(|_| invalid("invalid TCP address"))?;
                octets.extend(
                    u32::from_str_radix(hex, 16)
                        .map_err(|_| invalid("invalid TCP address"))?
                        .to_ne_bytes(),
                );
            }
            let ip = if ipv6 {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(octets).unwrap()))
            } else {
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(octets).unwrap()))
            };
            result.push(Listener {
                address: SocketAddr::new(ip, port),
                inode,
            });
        }
        Ok(result)
    }
    #[cfg(target_os = "linux")]
    mod descriptor;
    #[cfg(test)]
    mod tests;
}
