//! Rosetta validation tracer: one helper process for the whole machine.
//!
//! Rosetta checks that it runs under Virtualization.framework with an ioctl
//! (type byte `0x61`) that fails under Hypervisor.framework. Something has to
//! answer it by ptrace. Doing that from inside each x86_64 process's own
//! container needs an extra process there, which either takes the program's
//! PID (breaking `pg_ctl -w`, PID files and `docker stop`'s signals) or is left
//! as a zombie under a PID 1 that never reaps. So one helper at the machine's
//! root does it for every container instead:
//!
//! ```text
//! x86_64 exec -> binfmt_misc runs the pinned wrapper (rosetta-wrapper.c)
//!   proc connector: PROC_EVENT_EXEC, /proc/<pid>/exe is the wrapper -> seize
//!   wrapper: ioctl(-1, HANDSHAKE) until it returns 0 (set by the tracer)
//!   wrapper: execve(rosetta) in place, keeping its PID
//!   tracer:  answers the validation ioctl at its exit, then detaches
//! ```
//!
//! The helper is its own process (`smolvm-agent rosetta-tracer DEV INO`) so
//! the agent's own `waitpid` calls never see its tracees' ptrace stops, and
//! single-threaded: a `signalfd` for SIGCHLD and the connector socket are both
//! polled, and every tracee is waited for with `WNOHANG`.

/// argv[1] that runs this helper instead of the agent.
pub const TRACER_ARG: &str = "rosetta-tracer";

/// The ioctl request a wrapper sends (on fd -1) to ask "am I traced yet?".
/// Untraced, the kernel answers EBADF; the tracer makes it return 0. Keep in
/// sync with `HANDSHAKE_CMD` in `scripts/rosetta/rosetta-wrapper.c`.
pub const HANDSHAKE_CMD: u32 = 0x534d_5652;

/// Whether this invocation is the tracer helper.
pub fn requested() -> bool {
    std::env::args().nth(1).as_deref() == Some(TRACER_ARG)
}

/// What a syscall-entry stop asks of the tracer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Intercept {
    /// The wrapper's handshake: return 0 at the exit.
    Handshake,
    /// The 0x45-byte validation: write the magic string, return 1.
    Magic(u64),
    /// The 0x80-byte validation: zero the buffer, return 1.
    Zeroed(u64),
}

/// Classify a syscall entry by its number and first three arguments.
pub(crate) fn classify(nr: u64, args: [u64; 3]) -> Option<Intercept> {
    const SYS_IOCTL: u64 = 29; // aarch64
    if nr != SYS_IOCTL {
        return None;
    }
    let cmd = args[1] as u32;
    if args[0] as i32 == -1 && cmd == HANDSHAKE_CMD {
        return Some(Intercept::Handshake);
    }
    let ioc_type = (cmd >> 8) & 0xff;
    let ioc_size = (cmd >> 16) & 0x3fff;
    // The command number changed between macOS versions; the type byte and
    // size identify the validation.
    match (ioc_type, ioc_size) {
        (0x61, 0x45) => Some(Intercept::Magic(args[2])),
        (0x61, 0x80) => Some(Intercept::Zeroed(args[2])),
        _ => None,
    }
}

/// The bytes the 0x45-byte validation expects in its buffer.
pub(crate) fn magic_buffer() -> [u8; 0x45] {
    const MAGIC: &[u8] =
        "Our hard work\nby these words guarded\nplease don't steal\n\u{a9} Apple Inc\n".as_bytes();
    let mut buf = [0u8; 0x45];
    let len = MAGIC.len().min(buf.len() - 1);
    buf[..len].copy_from_slice(&MAGIC[..len]);
    buf
}

/// Exec events parsed from one proc connector datagram: the tgid of each
/// `PROC_EVENT_EXEC`.
pub(crate) fn exec_tgids(datagram: &[u8]) -> Vec<i32> {
    const NLMSG_HDR: usize = 16;
    const CN_MSG_HDR: usize = 20;
    const PROC_EVENT_EXEC: u32 = 2;
    let u32_at = |b: &[u8], at: usize| -> Option<u32> {
        b.get(at..at + 4)
            .map(|s| u32::from_ne_bytes(s.try_into().unwrap()))
    };
    let mut tgids = Vec::new();
    let mut at = 0;
    while let Some(len) = u32_at(datagram, at) {
        let len = len as usize;
        if len < NLMSG_HDR || at + len > datagram.len() {
            break;
        }
        let event = at + NLMSG_HDR + CN_MSG_HDR;
        // proc_event: what u32, cpu u32, timestamp u64, then the exec payload:
        // process_pid, process_tgid.
        if u32_at(datagram, event) == Some(PROC_EVENT_EXEC) {
            if let Some(tgid) = u32_at(datagram, event + 20) {
                tgids.push(tgid as i32);
            }
        }
        at += (len + 3) & !3;
    }
    tgids
}

/// Run the helper: `smolvm-agent rosetta-tracer DEV INO`, where DEV and INO
/// identify the pinned wrapper. Writes `R` to stdout once it listens.
#[cfg(target_os = "linux")]
pub fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    let (Some(dev), Some(ino)) = (
        args.get(2).and_then(|v| v.parse::<u64>().ok()),
        args.get(3).and_then(|v| v.parse::<u64>().ok()),
    ) else {
        eprintln!("usage: smolvm-agent rosetta-tracer DEV INO");
        return 2;
    };
    match linux::serve(dev, ino) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("rosetta-tracer: {e}");
            1
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn run() -> i32 {
    1
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{classify, exec_tgids, magic_buffer, Intercept};
    use std::collections::HashMap;
    use std::io::{self, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;

    const NETLINK_CONNECTOR: libc::c_int = 11;
    const CN_IDX_PROC: u32 = 1;
    const CN_VAL_PROC: u32 = 1;
    const PROC_CN_MCAST_LISTEN: u32 = 1;
    const PTRACE_GET_SYSCALL_INFO: i64 = 0x420e;
    const SYSCALL_INFO_ENTRY: u8 = 1;
    const SYSCALL_INFO_EXIT: u8 = 2;
    const PTRACE_EVENT_STOP: i32 = 128;

    fn check(rc: libc::c_long) -> io::Result<libc::c_long> {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc)
        }
    }

    /// Subscribe to process events; the socket then yields exec events.
    fn proc_connector() -> io::Result<OwnedFd> {
        // SAFETY: plain socket(2); the fd is owned below.
        let fd = check(unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                NETLINK_CONNECTOR,
            )
        } as libc::c_long)?;
        // SAFETY: fd is a fresh socket owned by nothing else.
        let sock = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        // SAFETY: sockaddr_nl is plain data; zeroed is a valid value.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_pid = std::process::id();
        addr.nl_groups = CN_IDX_PROC;
        // SAFETY: addr is a valid sockaddr_nl of the given length.
        check(unsafe {
            libc::bind(
                sock.as_raw_fd(),
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        } as libc::c_long)?;
        // nlmsghdr (16) + cn_msg (20) + op (4)
        let mut msg = Vec::with_capacity(40);
        msg.extend_from_slice(&40u32.to_ne_bytes()); // nlmsg_len
        msg.extend_from_slice(&(libc::NLMSG_DONE as u16).to_ne_bytes()); // nlmsg_type
        msg.extend_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
        msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_seq
        msg.extend_from_slice(&std::process::id().to_ne_bytes()); // nlmsg_pid
        msg.extend_from_slice(&CN_IDX_PROC.to_ne_bytes()); // cn_msg.id.idx
        msg.extend_from_slice(&CN_VAL_PROC.to_ne_bytes()); // cn_msg.id.val
        msg.extend_from_slice(&0u32.to_ne_bytes()); // seq
        msg.extend_from_slice(&0u32.to_ne_bytes()); // ack
        msg.extend_from_slice(&4u16.to_ne_bytes()); // len
        msg.extend_from_slice(&0u16.to_ne_bytes()); // flags
        msg.extend_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());
        // SAFETY: msg is a valid buffer of msg.len() bytes.
        check(unsafe {
            libc::send(
                sock.as_raw_fd(),
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
            )
        } as libc::c_long)?;
        Ok(sock)
    }

    /// SIGCHLD as a pollable fd (this process is single-threaded).
    fn sigchld_fd() -> io::Result<OwnedFd> {
        // SAFETY: sigset manipulation on a local; signalfd returns a new fd.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGCHLD);
            if libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = check(
                libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) as libc::c_long,
            )?;
            Ok(OwnedFd::from_raw_fd(fd as i32))
        }
    }

    pub(super) fn serve(dev: u64, ino: u64) -> io::Result<()> {
        let events = proc_connector()?;
        let sigchld = sigchld_fd()?;
        // Listening: let the agent register the interpreter.
        let mut stdout = io::stdout();
        let _ = stdout.write_all(b"R").and_then(|()| stdout.flush());
        // SAFETY: closing our stdout so the agent's read sees EOF after "R".
        unsafe { libc::close(1) };

        let mut tracees: HashMap<i32, Option<Intercept>> = HashMap::new();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let mut fds = [
                libc::pollfd {
                    fd: events.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: sigchld.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: fds is a valid array for the call.
            if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if fds[0].revents & libc::POLLIN != 0 {
                // SAFETY: buf is valid for buf.len() bytes.
                let n = unsafe {
                    libc::recv(
                        events.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if n > 0 {
                    for tgid in exec_tgids(&buf[..n as usize]) {
                        if !tracees.contains_key(&tgid) && is_wrapper(tgid, dev, ino) && seize(tgid)
                        {
                            tracees.insert(tgid, None);
                        }
                    }
                }
            }
            if fds[1].revents & libc::POLLIN != 0 {
                let mut info = [0u8; 128];
                // SAFETY: drains pending siginfo records into a local buffer.
                while unsafe {
                    libc::read(
                        sigchld.as_raw_fd(),
                        info.as_mut_ptr() as *mut libc::c_void,
                        info.len(),
                    )
                } > 0
                {}
            }
            // Ptrace stops raise SIGCHLD, but a connector event can also race
            // the first stop: check every tracee each round.
            let pids: Vec<i32> = tracees.keys().copied().collect();
            for pid in pids {
                step(pid, &mut tracees);
            }
        }
    }

    /// Whether `pid` is running the pinned wrapper.
    fn is_wrapper(pid: i32, dev: u64, ino: u64) -> bool {
        std::fs::metadata(format!("/proc/{pid}/exe"))
            .is_ok_and(|m| m.dev() == dev && m.ino() == ino)
    }

    fn ptrace(request: i64, pid: i32, addr: usize, data: usize) -> libc::c_long {
        // SAFETY: raw ptrace(2); callers pass addresses valid for the request.
        // The request's C type differs between glibc and musl, hence `as _`.
        unsafe {
            libc::ptrace(
                request as _,
                pid,
                addr as *mut libc::c_void,
                data as *mut libc::c_void,
            )
        }
    }

    fn seize(pid: i32) -> bool {
        ptrace(
            libc::PTRACE_SEIZE as i64,
            pid,
            0,
            libc::PTRACE_O_TRACESYSGOOD as usize,
        ) == 0
            && ptrace(libc::PTRACE_INTERRUPT as i64, pid, 0, 0) == 0
    }

    /// Handle every pending stop of `pid`.
    fn step(pid: i32, tracees: &mut HashMap<i32, Option<Intercept>>) {
        loop {
            let mut status = 0;
            // SAFETY: waitpid on our own tracee, status is a local.
            let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) };
            if rc == 0 {
                return;
            }
            if rc < 0 || libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                tracees.remove(&pid);
                return;
            }
            if !libc::WIFSTOPPED(status) {
                continue;
            }
            let sig = libc::WSTOPSIG(status);
            let event = status >> 16;
            if sig == (libc::SIGTRAP | 0x80) {
                if syscall_stop(pid, tracees) {
                    // Detached.
                    tracees.remove(&pid);
                    return;
                }
                ptrace(libc::PTRACE_SYSCALL as i64, pid, 0, 0);
            } else if event == PTRACE_EVENT_STOP {
                // A group stop (SIGSTOP and friends) stays stopped; the
                // interrupt stop after seizing resumes into syscall tracing.
                if matches!(
                    sig,
                    libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
                ) {
                    ptrace(libc::PTRACE_LISTEN as i64, pid, 0, 0);
                } else {
                    ptrace(libc::PTRACE_SYSCALL as i64, pid, 0, 0);
                }
            } else {
                // Signal-delivery stop: deliver it.
                ptrace(libc::PTRACE_SYSCALL as i64, pid, 0, sig as usize);
            }
        }
    }

    /// Handle one syscall stop; true once the tracee was detached.
    fn syscall_stop(pid: i32, tracees: &mut HashMap<i32, Option<Intercept>>) -> bool {
        // struct ptrace_syscall_info: op u8, pad, arch u32, ip u64, sp u64,
        // then entry { nr u64, args [u64; 6] } or exit { rval i64, .. }.
        let mut info = [0u8; 88];
        if ptrace(
            PTRACE_GET_SYSCALL_INFO,
            pid,
            info.len(),
            info.as_mut_ptr() as usize,
        ) <= 0
        {
            return false;
        }
        let word = |at: usize| u64::from_ne_bytes(info[at..at + 8].try_into().unwrap());
        let pending = tracees.get(&pid).copied().flatten();
        match info[0] {
            SYSCALL_INFO_ENTRY => {
                let found = classify(word(24), [word(32), word(40), word(48)]);
                tracees.insert(pid, found);
                false
            }
            SYSCALL_INFO_EXIT => {
                tracees.insert(pid, None);
                match pending {
                    None => false,
                    Some(Intercept::Handshake) => {
                        set_return(pid, 0);
                        false
                    }
                    Some(Intercept::Magic(addr)) => {
                        write_memory(pid, addr, &magic_buffer());
                        set_return(pid, 1);
                        ptrace(libc::PTRACE_DETACH as i64, pid, 0, 0);
                        true
                    }
                    Some(Intercept::Zeroed(addr)) => {
                        write_memory(pid, addr, &[0u8; 0x80]);
                        set_return(pid, 1);
                        ptrace(libc::PTRACE_DETACH as i64, pid, 0, 0);
                        true
                    }
                }
            }
            _ => false,
        }
    }

    /// Set the syscall's return register (x0 on aarch64).
    fn set_return(pid: i32, value: u64) {
        // user_pt_regs: regs[31], sp, pc, pstate.
        let mut regs = [0u64; 34];
        let mut iov = libc::iovec {
            iov_base: regs.as_mut_ptr() as *mut libc::c_void,
            iov_len: std::mem::size_of_val(&regs),
        };
        let iov_addr = &mut iov as *mut libc::iovec as usize;
        if ptrace(
            libc::PTRACE_GETREGSET as i64,
            pid,
            libc::NT_PRSTATUS as usize,
            iov_addr,
        ) == 0
        {
            // SAFETY: iov_base points at `regs`, which the kernel just filled.
            unsafe { *(iov.iov_base as *mut u64) = value };
            ptrace(
                libc::PTRACE_SETREGSET as i64,
                pid,
                libc::NT_PRSTATUS as usize,
                iov_addr,
            );
        }
    }

    fn write_memory(pid: i32, addr: u64, bytes: &[u8]) {
        let local = libc::iovec {
            iov_base: bytes.as_ptr() as *mut libc::c_void,
            iov_len: bytes.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: bytes.len(),
        };
        // SAFETY: both iovecs describe valid ranges (remote is the tracee's).
        unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_and_both_validations_are_recognised_and_nothing_else() {
        let ioctl = 29;
        assert_eq!(
            classify(ioctl, [u64::MAX, u64::from(HANDSHAKE_CMD), 0]),
            Some(Intercept::Handshake)
        );
        // 32-bit -1 as the fd also counts (the kernel reads an int).
        assert_eq!(
            classify(ioctl, [0xffff_ffff, u64::from(HANDSHAKE_CMD), 0]),
            Some(Intercept::Handshake)
        );
        let magic_cmd = (0x45u64 << 16) | (0x61 << 8) | 0x22;
        let zero_cmd = (0x80u64 << 16) | (0x61 << 8) | 0x23;
        assert_eq!(
            classify(ioctl, [3, magic_cmd, 0x1000]),
            Some(Intercept::Magic(0x1000))
        );
        assert_eq!(
            classify(ioctl, [3, zero_cmd, 0x2000]),
            Some(Intercept::Zeroed(0x2000))
        );
        assert_eq!(
            classify(ioctl, [3, u64::from(HANDSHAKE_CMD), 0]),
            None,
            "only on fd -1"
        );
        assert_eq!(classify(ioctl, [3, (0x10 << 16) | (0x61 << 8), 0]), None);
        assert_eq!(
            classify(63, [u64::MAX, u64::from(HANDSHAKE_CMD), 0]),
            None,
            "not an ioctl"
        );
    }

    #[test]
    fn the_magic_buffer_carries_the_string_nul_terminated() {
        let buf = magic_buffer();
        assert!(buf.starts_with(b"Our hard work\n"));
        assert_eq!(buf[buf.len() - 1], 0);
    }

    #[test]
    fn the_c_wrapper_sends_the_same_handshake() {
        let source = include_str!("../../../scripts/rosetta/rosetta-wrapper.c");
        assert!(
            source.contains(&format!("HANDSHAKE_CMD 0x{HANDSHAKE_CMD:x}")),
            "rosetta-wrapper.c and rosetta_tracer.rs must agree on the handshake"
        );
    }

    fn nlmsg(what: u32, tgid: u32) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&60u32.to_ne_bytes()); // len: 16 + 20 + 24
        m.extend_from_slice(&[0u8; 12]);
        m.extend_from_slice(&[0u8; 20]); // cn_msg
        m.extend_from_slice(&what.to_ne_bytes());
        m.extend_from_slice(&[0u8; 12]); // cpu, timestamp
        m.extend_from_slice(&tgid.to_ne_bytes()); // process_pid
        m.extend_from_slice(&tgid.to_ne_bytes()); // process_tgid
        m
    }

    #[test]
    fn exec_events_are_picked_out_of_a_connector_datagram() {
        let mut datagram = nlmsg(2, 41);
        datagram.extend(nlmsg(1, 42)); // a fork event
        datagram.extend(nlmsg(2, 43));
        assert_eq!(exec_tgids(&datagram), vec![41, 43]);
        assert!(
            exec_tgids(&datagram[..30]).is_empty(),
            "a truncated message is ignored"
        );
    }
}
