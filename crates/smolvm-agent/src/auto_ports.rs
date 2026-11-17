//! Guest side of automatic port publishing: report listening TCP ports.
//!
//! Enabled by [`guest_env::AUTO_PORTS`]. About once a second this reads
//! `/proc/net/tcp` and `/proc/net/tcp6`, keeps the ports the host's port
//! forwarder can reach (bound to the wildcard address or to loopback, see
//! [`auto_ports::forwardable_ports`]), and when that set differs from the
//! last one sent, connects out on [`ports::AUTO_PORTS`] and sends it whole.
//! The host publishes and unpublishes to match.
//!
//! Polling rather than watching: the kernel has no listen-socket event a
//! process can subscribe to without netlink sock_diag plumbing, and reading
//! two small proc files a second costs microseconds. A port appears on the
//! host within about a second of the server calling `listen()`.
//!
//! Every server in the guest's root network namespace is seen, which covers
//! image workloads (their containers share it), `machine exec` processes, and
//! `docker run -p`, whose userland proxy listens in the root namespace. A
//! server inside a namespace of its own (a Docker container without a
//! published port, `docker run --network none`) is not, and neither is a
//! port Docker publishes only through iptables (`userland-proxy: false`).
//! The agent itself listens only on vsock, so it has no TCP port to exclude.

use smolvm_protocol::auto_ports::{self, ListeningReport};
use smolvm_protocol::{guest_env, ports};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::time::Duration;

/// How often the listening set is read.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The tables listening sockets are read from. A guest without IPv6 has no
/// `tcp6`; its absence is an empty table, not an error.
const PROC_NET_TCP: [&str; 2] = ["/proc/net/tcp", "/proc/net/tcp6"];

/// Whether the host asked for automatic port publishing.
pub fn is_enabled() -> bool {
    std::env::var(guest_env::AUTO_PORTS).as_deref() == Ok(guest_env::VALUE_ON)
}

/// Start the listening-port watcher in a background thread.
pub fn start() {
    let spawned = std::thread::Builder::new()
        .name("auto-ports".into())
        .spawn(|| {
            tracing::info!(vsock_port = ports::AUTO_PORTS, "auto ports watcher started");
            let mut reporter = Reporter::default();
            loop {
                reporter.tick(read_listening(), connect_to_host);
                std::thread::sleep(POLL_INTERVAL);
            }
        });
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "auto ports watcher could not start");
    }
}

/// The ports currently worth publishing.
fn read_listening() -> BTreeSet<u16> {
    let mut tables = String::new();
    for path in PROC_NET_TCP {
        if let Ok(text) = std::fs::read_to_string(path) {
            tables.push_str(&text);
        }
    }
    auto_ports::forwardable_ports(&auto_ports::parse_listeners(&tables))
}

fn connect_to_host() -> io::Result<crate::vsock::VsockStream> {
    crate::vsock::connect(ports::AUTO_PORTS)
}

/// A connection the watcher reports over.
trait ReportSink: Write {
    /// Whether the host has gone away. The host never writes on this
    /// connection, so anything readable means it was closed (a restored or
    /// branched guest's connections are reset), and the next report must go
    /// over a new one even if the set has not changed.
    fn peer_closed(&self) -> bool;
}

impl ReportSink for crate::vsock::VsockStream {
    fn peer_closed(&self) -> bool {
        use std::os::unix::io::AsRawFd;
        let mut fd = libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `fd` is one valid pollfd for the duration of the call.
        let ready = unsafe { libc::poll(&mut fd, 1, 0) };
        ready != 0
    }
}

/// Sends the listening set whenever it changes or the connection is new.
struct Reporter<S> {
    connection: Option<S>,
    /// The set the host last received over `connection`.
    sent: Option<BTreeSet<u16>>,
}

impl<S> Default for Reporter<S> {
    fn default() -> Self {
        Self {
            connection: None,
            sent: None,
        }
    }
}

impl<S: ReportSink> Reporter<S> {
    /// One poll: report `listening` if the host has not seen it yet. A host
    /// that cannot be reached (its port is not registered, or the connection
    /// broke) is retried on the next tick, quietly: a branch child of an
    /// auto-ports machine may boot without it.
    fn tick(&mut self, listening: BTreeSet<u16>, connect: impl FnOnce() -> io::Result<S>) {
        if self.connection.as_ref().is_some_and(S::peer_closed) {
            self.connection = None;
        }
        if self.connection.is_none() {
            self.sent = None;
            match connect() {
                Ok(connection) => self.connection = Some(connection),
                Err(e) => {
                    tracing::trace!(error = %e, "auto ports host not reachable");
                    return;
                }
            }
        }
        if self.sent.as_ref() == Some(&listening) {
            return;
        }
        let line = ListeningReport::new(&listening).encode();
        let Some(connection) = self.connection.as_mut() else {
            return;
        };
        match connection.write_all(line.as_bytes()) {
            Ok(()) => {
                tracing::debug!(ports = ?listening, "auto ports reported");
                self.sent = Some(listening);
            }
            Err(e) => {
                tracing::debug!(error = %e, "auto ports report failed; reconnecting");
                self.connection = None;
                self.sent = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A fake host connection recording every line it was sent.
    #[derive(Clone, Default)]
    struct FakeHost {
        lines: Rc<RefCell<Vec<String>>>,
        closed: Rc<RefCell<bool>>,
        fail_writes: Rc<RefCell<bool>>,
    }

    impl Write for FakeHost {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if *self.fail_writes.borrow() {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            self.lines
                .borrow_mut()
                .push(String::from_utf8(buf.to_vec()).unwrap());
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ReportSink for FakeHost {
        fn peer_closed(&self) -> bool {
            *self.closed.borrow()
        }
    }

    fn set(ports: &[u16]) -> BTreeSet<u16> {
        ports.iter().copied().collect()
    }

    #[test]
    fn a_report_is_sent_on_connect_and_on_each_change_only() {
        let host = FakeHost::default();
        let mut reporter = Reporter::default();
        let connect = || Ok(host.clone());

        reporter.tick(set(&[]), connect);
        reporter.tick(set(&[]), connect);
        reporter.tick(set(&[8000]), connect);
        reporter.tick(set(&[8000]), connect);
        reporter.tick(set(&[8000, 3000]), connect);
        reporter.tick(set(&[3000]), connect);

        assert_eq!(
            *host.lines.borrow(),
            [
                "{\"tcp\":[]}\n",
                "{\"tcp\":[8000]}\n",
                "{\"tcp\":[3000,8000]}\n",
                "{\"tcp\":[3000]}\n",
            ],
            "the first connection learns the (empty) set; later ticks send only changes"
        );
    }

    #[test]
    fn an_unreachable_host_is_retried_and_then_gets_the_current_set() {
        let host = FakeHost::default();
        let mut reporter: Reporter<FakeHost> = Reporter::default();
        reporter.tick(
            set(&[8000]),
            || Err(io::ErrorKind::ConnectionRefused.into()),
        );
        assert!(host.lines.borrow().is_empty());
        reporter.tick(set(&[8000]), || Ok(host.clone()));
        assert_eq!(*host.lines.borrow(), ["{\"tcp\":[8000]}\n"]);
    }

    #[test]
    fn a_closed_or_broken_connection_is_replaced_and_resent_the_same_set() {
        let first = FakeHost::default();
        let mut reporter = Reporter::default();
        reporter.tick(set(&[8000]), || Ok(first.clone()));

        // A restored guest: the host end is gone though nothing changed.
        *first.closed.borrow_mut() = true;
        let second = FakeHost::default();
        reporter.tick(set(&[8000]), || Ok(second.clone()));
        assert_eq!(*second.lines.borrow(), ["{\"tcp\":[8000]}\n"]);

        // A write that fails drops the connection; the next tick reconnects.
        *second.fail_writes.borrow_mut() = true;
        reporter.tick(set(&[8000, 9000]), || Ok(second.clone()));
        let third = FakeHost::default();
        reporter.tick(set(&[8000, 9000]), || Ok(third.clone()));
        assert_eq!(*third.lines.borrow(), ["{\"tcp\":[8000,9000]}\n"]);
    }
}
