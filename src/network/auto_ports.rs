//! Host side of automatic port publishing (`--auto-ports`).
//!
//! The guest agent reports the TCP ports it listens on whenever that set
//! changes (see [`smolvm_protocol::auto_ports`]), over a vsock port libkrun
//! bridges to [`AUTO_PORTS_SOCKET`] in the machine's directory. This process,
//! the machine's VMM, publishes each reported port `P` as host `127.0.0.1:P`
//! (and `[::1]:P`) through a [`PortForwarder`] of its own, the same live
//! forwarder `machine update -p` uses on TSI, and closes it once a report no
//! longer names it. The forwarder reaches the guest port on the guest's
//! loopback, so a dev server bound to `127.0.0.1` inside the machine is
//! reachable too, on every network backend.
//!
//! The rules, chosen to be predictable rather than clever:
//!
//! - The host port is always the guest port. A host port already taken (by
//!   any process, another machine included) is skipped and logged once; no
//!   other port is picked. It is retried with every later report.
//! - Only loopback. When `SMOLVM_PUBLISH_ADDR` widens published ports beyond
//!   loopback (fleet nodes), auto ports stay off. Ports below 1024 are not
//!   published automatically either: macOS binds them only on the wildcard
//!   address, and a Linux user cannot bind them at all.
//! - Declared ports win. A guest port already published with `-p`, or whose
//!   host port a `-p` mapping uses, is left to that mapping; excluded ports
//!   (`--auto-ports-exclude`) are never published.
//!
//! What is published is written to [`AUTO_PORTS_FILE`] beside the socket, so
//! `machine status` and `machine ls --json` can show it while the machine runs.
//! Everything here dies with the VMM process, which closes every listener.

use super::port_forward::PortForwarder;
use serde::{Deserialize, Serialize};
use smolvm_network::PortMapping;
use smolvm_protocol::auto_ports::{ListeningReport, MAX_REPORT_BYTES};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Host file name of the socket the guest's reports arrive on.
pub const AUTO_PORTS_SOCKET: &str = "auto-ports.sock";

/// File in the machine's directory holding what auto ports published.
pub const AUTO_PORTS_FILE: &str = "auto-ports.json";

/// The lowest port published automatically; see the module docs.
pub const MIN_AUTO_PORT: u16 = 1024;

/// How a skip reason for a host port that could not be bound starts.
const UNAVAILABLE: &str = "host port unavailable";

/// The guest ports `-p` publishes on this machine right now, as `(host,
/// guest)` TCP pairs. One VMM process runs one machine, so the declared set
/// is process state: the launcher records the boot set and the ports control
/// socket records every live change, on whichever backend serves it.
static DECLARED_PORTS: Mutex<Vec<(u16, u16)>> = Mutex::new(Vec::new());

/// Record the TCP ports this machine publishes with `-p` now.
pub fn note_declared_ports(ports: &[PortMapping]) {
    let tcp = ports
        .iter()
        .filter(|mapping| mapping.protocol == smolvm_network::PortProtocol::Tcp)
        .map(|mapping| (mapping.host, mapping.guest))
        .collect();
    *DECLARED_PORTS.lock().unwrap_or_else(|e| e.into_inner()) = tcp;
}

fn declared_ports() -> Vec<(u16, u16)> {
    DECLARED_PORTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// What auto ports did with the ports the guest reported last.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoPortsState {
    /// Ports published as host `127.0.0.1:P` to guest `P`, ascending.
    pub published: Vec<u16>,
    /// Reported ports left unpublished, and why.
    pub skipped: Vec<SkippedPort>,
}

/// A listening guest port auto ports did not publish.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedPort {
    /// The guest port.
    pub port: u16,
    /// Why it was not published.
    pub reason: String,
}

/// What auto ports published for the running machine whose directory is
/// `vm_dir`, if it runs with them. Only meaningful while the machine runs:
/// the file outlives a stopped VMM until its next start replaces it.
pub fn read_state(vm_dir: &Path) -> Option<AutoPortsState> {
    let text = std::fs::read_to_string(vm_dir.join(AUTO_PORTS_FILE)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Something that publishes exactly a set of TCP mappings, all or nothing:
/// the [`PortForwarder`], or a test double.
pub trait PublishPorts: Send {
    /// Publish exactly `ports`; a host port that cannot be bound fails the
    /// call and leaves the set as it was.
    fn replace(&self, ports: &[PortMapping]) -> Result<(), String>;
}

impl PublishPorts for PortForwarder {
    fn replace(&self, ports: &[PortMapping]) -> Result<(), String> {
        PortForwarder::replace(self, ports)
    }
}

/// Turns guest reports into published host ports.
pub struct AutoPublisher<P> {
    publish: P,
    exclude: BTreeSet<u16>,
    declared: Box<dyn Fn() -> Vec<(u16, u16)> + Send>,
    published: BTreeSet<u16>,
    skipped: BTreeMap<u16, String>,
}

impl<P: PublishPorts> AutoPublisher<P> {
    /// A publisher with nothing published yet. `declared` returns the
    /// `(host, guest)` TCP pairs `-p` publishes at the moment it is called.
    pub fn new(
        publish: P,
        exclude: &[u16],
        declared: impl Fn() -> Vec<(u16, u16)> + Send + 'static,
    ) -> Self {
        Self {
            publish,
            exclude: exclude.iter().copied().collect(),
            declared: Box::new(declared),
            published: BTreeSet::new(),
            skipped: BTreeMap::new(),
        }
    }

    /// Make the published ports match `listening`, the guest's latest report.
    pub fn apply(&mut self, listening: &BTreeSet<u16>) -> AutoPortsState {
        let declared = (self.declared)();
        let mut skipped = BTreeMap::new();
        let mut wanted = BTreeSet::new();
        for &port in listening {
            let reason = if self.exclude.contains(&port) {
                Some("excluded".to_string())
            } else if port < MIN_AUTO_PORT {
                Some(format!(
                    "below {MIN_AUTO_PORT}; publish it with -p HOST:{port}"
                ))
            } else if let Some(&(host, _)) = declared.iter().find(|(_, guest)| *guest == port) {
                Some(format!("published with -p {host}:{port}"))
            } else if let Some(&(_, guest)) = declared.iter().find(|(host, _)| *host == port) {
                Some(format!("host port taken by -p {port}:{guest}"))
            } else {
                None
            };
            match reason {
                Some(reason) => {
                    skipped.insert(port, reason);
                }
                None => {
                    wanted.insert(port);
                }
            }
        }

        // Close what is no longer wanted first, so a port moving between
        // auto and declared never collides with itself.
        let mut kept: BTreeSet<u16> = self.published.intersection(&wanted).copied().collect();
        if kept != self.published {
            if let Err(error) = self.publish.replace(&mappings(&kept)) {
                tracing::warn!(%error, "auto ports: closing ports failed");
                kept = self.published.clone();
            }
            for gone in self.published.difference(&kept) {
                tracing::info!(port = gone, "auto ports: unpublished");
            }
        }

        // Then add each new port on its own, so one taken host port does not
        // keep the others from being published.
        let new: Vec<u16> = wanted.difference(&kept).copied().collect();
        for port in new {
            let mut next = kept.clone();
            next.insert(port);
            match self.publish.replace(&mappings(&next)) {
                Ok(()) => {
                    tracing::info!(port, "auto ports: published 127.0.0.1:{port}");
                    kept = next;
                }
                Err(error) => {
                    skipped.insert(port, format!("{UNAVAILABLE}: {error}"));
                }
            }
        }
        // Say once why a port is not published, not on every report.
        for (port, reason) in &skipped {
            if self.skipped.contains_key(port) {
                continue;
            }
            if reason.starts_with(UNAVAILABLE) {
                tracing::warn!(port, reason = %reason, "auto ports: skipped");
            } else {
                tracing::info!(port, reason = %reason, "auto ports: not published");
            }
        }
        self.published = kept;
        self.skipped = skipped;
        self.state()
    }

    /// What is published now.
    pub fn state(&self) -> AutoPortsState {
        AutoPortsState {
            published: self.published.iter().copied().collect(),
            skipped: self
                .skipped
                .iter()
                .map(|(&port, reason)| SkippedPort {
                    port,
                    reason: reason.clone(),
                })
                .collect(),
        }
    }
}

fn mappings(ports: &BTreeSet<u16>) -> Vec<PortMapping> {
    ports
        .iter()
        .map(|&port| PortMapping::new(port, port))
        .collect()
}

/// Start auto ports for the machine whose directory is `vm_dir`: a
/// forwarder relaying through `port_forward_socket`, and a listener on
/// [`AUTO_PORTS_SOCKET`] for the guest's reports. Returns the listener's
/// path for libkrun to bridge, or `None` (logged) when auto ports cannot run.
pub fn start(vm_dir: &Path, port_forward_socket: &Path, exclude: &[u16]) -> Option<PathBuf> {
    let publish_addr = smolvm_network::publish_bind::publish_addr();
    if !publish_addr.is_loopback() {
        tracing::warn!(
            %publish_addr,
            "auto ports disabled: published ports are widened beyond loopback here"
        );
        return None;
    }
    let state_file = vm_dir.join(AUTO_PORTS_FILE);
    let socket = vm_dir.join(AUTO_PORTS_SOCKET);
    let started = PortForwarder::new(port_forward_socket).and_then(|forwarder| {
        let _ = std::fs::remove_file(&socket);
        let listener = crate::platform::uds::UdsListener::bind(&socket)?;
        Ok((forwarder, listener))
    });
    let (forwarder, listener) = match started {
        Ok(started) => started,
        Err(error) => {
            tracing::warn!(%error, "auto ports disabled");
            return None;
        }
    };
    let publisher = Arc::new(Mutex::new(AutoPublisher::new(
        forwarder,
        exclude,
        declared_ports,
    )));
    write_state(&state_file, &AutoPortsState::default());
    let spawned = std::thread::Builder::new()
        .name("auto-ports".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else {
                    continue;
                };
                // One connection at a time is the norm; a restored guest
                // opens a new one while the old one is still closing.
                let publisher = Arc::clone(&publisher);
                let state_file = state_file.clone();
                let _ = std::thread::Builder::new()
                    .name("auto-ports-conn".into())
                    .spawn(move || serve_reports(stream, &publisher, &state_file));
            }
        });
    match spawned {
        Ok(_) => Some(socket),
        Err(error) => {
            tracing::warn!(%error, "auto ports disabled");
            None
        }
    }
}

/// Apply every report line from one guest connection until it closes.
fn serve_reports<P: PublishPorts>(
    stream: impl Read,
    publisher: &Mutex<AutoPublisher<P>>,
    state_file: &Path,
) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut reader)
            .take(MAX_REPORT_BYTES as u64 + 1)
            .read_line(&mut line)
        {
            Ok(0) | Err(_) => return,
            Ok(n) if n > MAX_REPORT_BYTES => {
                tracing::warn!("auto ports: report too long; dropping the connection");
                return;
            }
            Ok(_) => {}
        }
        let Some(report) = ListeningReport::decode(&line) else {
            tracing::debug!("auto ports: ignoring an unreadable report");
            continue;
        };
        let state = publisher
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .apply(&report.ports());
        write_state(state_file, &state);
    }
}

/// Replace the state file whole, so a reader never sees half of it.
fn write_state(path: &Path, state: &AutoPortsState) {
    let Ok(json) = serde_json::to_vec(state) else {
        return;
    };
    let staging = path.with_extension("json.tmp");
    if let Err(error) =
        std::fs::write(&staging, json).and_then(|()| std::fs::rename(&staging, path))
    {
        tracing::debug!(%error, "auto ports: state file not written");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A publisher double: refuses any set holding a port in `taken`, and
    /// records the last set it accepted.
    #[derive(Default)]
    struct FakeHost {
        taken: Mutex<BTreeSet<u16>>,
        live: Mutex<Vec<u16>>,
        calls: Mutex<usize>,
    }

    impl PublishPorts for Arc<FakeHost> {
        fn replace(&self, ports: &[PortMapping]) -> Result<(), String> {
            *self.calls.lock().unwrap() += 1;
            let taken = self.taken.lock().unwrap();
            if let Some(port) = ports.iter().find(|m| taken.contains(&m.host)) {
                return Err(format!("{}: address in use", port.host));
            }
            assert!(
                ports.iter().all(|m| m.host == m.guest),
                "same port on both sides"
            );
            *self.live.lock().unwrap() = ports.iter().map(|m| m.host).collect();
            Ok(())
        }
    }

    fn set(ports: &[u16]) -> BTreeSet<u16> {
        ports.iter().copied().collect()
    }

    fn publisher(
        host: &Arc<FakeHost>,
        exclude: &[u16],
        declared: Vec<(u16, u16)>,
    ) -> AutoPublisher<Arc<FakeHost>> {
        AutoPublisher::new(Arc::clone(host), exclude, move || declared.clone())
    }

    #[test]
    fn ports_follow_the_reports_as_they_come_and_go() {
        let host = Arc::new(FakeHost::default());
        let mut auto = publisher(&host, &[], Vec::new());

        assert_eq!(auto.apply(&set(&[8000])).published, [8000]);
        assert_eq!(*host.live.lock().unwrap(), [8000]);

        assert_eq!(auto.apply(&set(&[8000, 3000])).published, [3000, 8000]);
        assert_eq!(*host.live.lock().unwrap(), [3000, 8000]);

        let state = auto.apply(&set(&[3000]));
        assert_eq!(state.published, [3000]);
        assert!(state.skipped.is_empty());
        assert_eq!(*host.live.lock().unwrap(), [3000], "8000 stopped listening");

        assert!(auto.apply(&set(&[])).published.is_empty());
        assert!(host.live.lock().unwrap().is_empty());
    }

    #[test]
    fn an_unchanged_report_touches_nothing() {
        let host = Arc::new(FakeHost::default());
        let mut auto = publisher(&host, &[], Vec::new());
        auto.apply(&set(&[8000]));
        let calls = *host.calls.lock().unwrap();
        auto.apply(&set(&[8000]));
        assert_eq!(*host.calls.lock().unwrap(), calls);
    }

    #[test]
    fn a_taken_host_port_is_skipped_without_blocking_the_rest_and_retried_later() {
        let host = Arc::new(FakeHost::default());
        host.taken.lock().unwrap().insert(5000);
        let mut auto = publisher(&host, &[], Vec::new());

        let state = auto.apply(&set(&[5000, 8000]));
        assert_eq!(state.published, [8000], "no other host port is chosen");
        assert_eq!(state.skipped.len(), 1);
        assert_eq!(state.skipped[0].port, 5000);
        assert!(state.skipped[0].reason.starts_with(UNAVAILABLE));
        assert!(state.skipped[0].reason.contains("address in use"));

        // The other process lets go; the next report publishes it.
        host.taken.lock().unwrap().clear();
        let state = auto.apply(&set(&[5000, 8000]));
        assert_eq!(state.published, [5000, 8000]);
        assert!(state.skipped.is_empty());
    }

    #[test]
    fn excluded_privileged_and_declared_ports_are_not_published() {
        let host = Arc::new(FakeHost::default());
        let declared = vec![(18080, 8080), (9000, 9999)];
        let mut auto = publisher(&host, &[5432], declared);

        let state = auto.apply(&set(&[80, 5432, 8080, 9000, 3000]));
        assert_eq!(state.published, [3000]);
        let reasons: BTreeMap<u16, String> = state
            .skipped
            .into_iter()
            .map(|s| (s.port, s.reason))
            .collect();
        assert_eq!(reasons[&5432], "excluded");
        assert!(reasons[&80].contains("below 1024"), "{}", reasons[&80]);
        assert_eq!(reasons[&8080], "published with -p 18080:8080");
        assert_eq!(reasons[&9000], "host port taken by -p 9000:9999");
    }

    #[test]
    fn a_port_declared_later_is_handed_over_to_its_mapping() {
        let host = Arc::new(FakeHost::default());
        let declared = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&declared);
        let mut auto =
            AutoPublisher::new(Arc::clone(&host), &[], move || seen.lock().unwrap().clone());
        assert_eq!(auto.apply(&set(&[8080])).published, [8080]);
        *declared.lock().unwrap() = vec![(18080, 8080)];
        let state = auto.apply(&set(&[8080]));
        assert!(state.published.is_empty());
        assert!(host.live.lock().unwrap().is_empty());
    }

    #[test]
    fn report_lines_are_applied_in_order_and_garbage_is_skipped() {
        let host = Arc::new(FakeHost::default());
        let auto = Mutex::new(publisher(&host, &[], Vec::new()));
        let dir = tempfile::tempdir().unwrap();
        let state_file = dir.path().join(AUTO_PORTS_FILE);
        let input = "{\"tcp\":[8000,3000]}\nnot json\n{\"tcp\":[3000],\"later\":1}\n";
        serve_reports(input.as_bytes(), &auto, &state_file);
        assert_eq!(*host.live.lock().unwrap(), [3000]);
        let state = read_state(dir.path()).unwrap();
        assert_eq!(state.published, [3000]);
    }

    #[test]
    fn an_overlong_report_drops_the_connection_and_changes_nothing() {
        let host = Arc::new(FakeHost::default());
        let auto = Mutex::new(publisher(&host, &[], Vec::new()));
        let dir = tempfile::tempdir().unwrap();
        let long = format!("{{\"tcp\":[{}]}}\n", "8000,".repeat(MAX_REPORT_BYTES / 4));
        serve_reports(long.as_bytes(), &auto, &dir.path().join(AUTO_PORTS_FILE));
        assert!(host.live.lock().unwrap().is_empty());
        assert_eq!(*host.calls.lock().unwrap(), 0);
    }

    /// The real forwarder: a taken host port is skipped, the free one serves
    /// the guest port of the same number, and an unreported one closes.
    #[cfg(unix)]
    #[test]
    fn the_forwarder_publishes_free_ports_and_skips_taken_ones() {
        use std::io::Write;
        use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir
            .path()
            .join(super::super::port_forward::PORT_FORWARD_SOCKET);
        // Stands in for libkrun's bridge to the guest: answers with the guest
        // port the forwarder named.
        let guest = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::thread::spawn(move || {
            for stream in guest.incoming() {
                let mut stream = stream.unwrap();
                let mut header = String::new();
                let mut byte = [0u8; 1];
                while stream.read_exact(&mut byte).is_ok() && byte[0] != b'\n' {
                    header.push(byte[0] as char);
                }
                let _ = stream.write_all(format!("guest {header}").as_bytes());
            }
        });
        let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let taken_port = taken.local_addr().unwrap().port();
        let free_port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let forwarder = PortForwarder::new(&socket).unwrap();
        let mut auto = AutoPublisher::new(forwarder, &[], Vec::new);
        let state = auto.apply(&set(&[taken_port, free_port]));
        assert_eq!(state.published, [free_port]);
        assert_eq!(state.skipped.len(), 1);
        assert_eq!(state.skipped[0].port, taken_port);

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, free_port)).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        assert_eq!(
            reply,
            format!("guest {free_port}"),
            "host P reaches guest P"
        );

        assert!(auto.apply(&set(&[])).published.is_empty());
        // Closed by the time apply returns; the freed port may already belong
        // to another test, so only check nothing of ours answers on it.
        if let Ok(mut late) = TcpStream::connect((Ipv4Addr::LOCALHOST, free_port)) {
            late.set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let _ = late.shutdown(Shutdown::Write);
            let mut reply = String::new();
            let _ = late.read_to_string(&mut reply);
            assert!(!reply.starts_with("guest "), "unpublished: {reply:?}");
        }
        drop(taken);
    }

    #[test]
    fn declared_ports_keep_only_tcp() {
        note_declared_ports(&[
            PortMapping::new(18080, 8080),
            PortMapping::with_protocol(5353, 53, smolvm_network::PortProtocol::Udp),
        ]);
        assert_eq!(declared_ports(), [(18080, 8080)]);
        note_declared_ports(&[]);
    }
}
