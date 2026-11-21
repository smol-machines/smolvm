//! Pin the actual OCI exec process before letting it run user code.
use crate::{error_codes, interactive_control::Registration, AgentResponse, ReadWrite, WireStream};
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use smolvm_protocol::{interactive_control::Session, WorkloadTarget};
use std::{
    fs::File,
    io::{self, IoSlice, IoSliceMut, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Child, Command},
    time::Duration,
};

const HELPER: &str = "controlled-exec";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

pub fn helper_requested() -> bool {
    std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new(HELPER))
}

pub fn run_helper() -> i32 {
    match helper() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("smolvm controlled exec: {error}");
            if error.kind() == io::ErrorKind::NotFound {
                127
            } else {
                126
            }
        }
    }
}

fn helper() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(2).collect();
    let parse_fd = |i: usize| -> io::Result<i32> {
        args.get(i)
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse().ok())
            .filter(|fd| *fd >= 3)
            .ok_or_else(|| io::Error::other("invalid inherited descriptor"))
    };
    let executable = parse_fd(0)?;
    let socket = parse_fd(1)?;
    if executable == socket || args.len() < 4 || (args[2] != "--" && args[2] != "--builtin") {
        return Err(io::Error::other("invalid helper invocation"));
    }
    // SAFETY: this private helper invocation owns the two inherited descriptors.
    let executable = unsafe { OwnedFd::from_raw_fd(executable) };
    let mut socket = unsafe { UnixStream::from_raw_fd(socket) };
    // Crun has already applied namespaces, credentials and OCI restrictions.
    // Establish an exec-owned group, retaining crun's controlling TTY session.
    unsafe {
        if libc::getpgrp() != libc::getpid() && libc::setsid() < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // Open our own identity while we are alive and waiting. Passing this fd
    // avoids a PID-file lookup/reuse race, including for very fast commands.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let process = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let fds = [process.as_raw_fd()];
    sendmsg::<()>(
        socket.as_raw_fd(),
        &[IoSlice::new(b"P")],
        &[ControlMessage::ScmRights(&fds)],
        MsgFlags::MSG_NOSIGNAL,
        None,
    )?;
    drop(process);
    let mut ready = [0];
    socket.read_exact(&mut ready)?;
    if ready != *b"G" {
        return Err(io::Error::other("exec was not admitted"));
    }
    drop(socket);
    drop(executable);
    if args[2] == "--builtin" {
        return crate::builtin_exec::run(&args[3..]);
    }
    // No helper process survives: the requested command keeps this PID/group.
    Err(Command::new(&args[3]).args(&args[4..]).exec())
}

fn receive_process(socket: &UnixStream) -> io::Result<OwnedFd> {
    let mut byte = [0];
    let mut vectors = [IoSliceMut::new(&mut byte)];
    let mut ancillary = nix::cmsg_space!([i32; 4]);
    let message = recvmsg::<()>(
        socket.as_raw_fd(),
        &mut vectors,
        Some(&mut ancillary),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )?;
    let mut descriptors = Vec::new();
    for cmsg in message.cmsgs() {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            // SAFETY: received SCM_RIGHTS descriptors are now owned by us.
            descriptors.extend(
                fds.into_iter()
                    .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
            );
        }
    }
    let valid = message.bytes == 1 && !message.flags.contains(MsgFlags::MSG_CTRUNC);
    if !valid || byte != *b"P" || descriptors.len() != 1 {
        return Err(io::Error::other("invalid controlled exec handshake"));
    }
    Ok(descriptors.pop().unwrap())
}

struct OwnedCommand {
    child: Child,
    control: Registration,
    terminate_on_drop: bool,
}

impl Drop for OwnedCommand {
    fn drop(&mut self) {
        if self.terminate_on_drop {
            self.control.terminate();
        }
        if matches!(self.child.try_wait(), Ok(None)) {
            crate::process::kill_child_tree(&mut self.child);
        }
        let _ = self.child.wait();
    }
}

pub fn serve(
    stream: &mut WireStream<impl ReadWrite>,
    session: Session,
) -> Result<(), Box<dyn std::error::Error>> {
    // All error paths use the normal agent response, and owned command cleanup
    // completes before an error response can block on its transport.
    let result = execute(stream, session);
    match result {
        Ok(exit_code) => crate::send_response(
            stream,
            &AgentResponse::Exited {
                exit_code,
                oom: false,
            },
        ),
        Err(error) => crate::send_response(
            stream,
            &AgentResponse::from_err(error, error_codes::EXEC_FAILED),
        ),
    }
}

fn execute(
    stream: &mut WireStream<impl ReadWrite>,
    session: Session,
) -> Result<i32, Box<dyn std::error::Error>> {
    let target = session.target.as_ref().ok_or("missing controlled target")?;
    target.validate()?;
    let WorkloadTarget::Container { image, overlay_id } = target else {
        return Err("expected image target".into());
    };
    session.validate_operation()?;
    if session
        .terminal
        .as_ref()
        .is_some_and(|t| t.cols == 0 || t.rows == 0 || t.modes.len() > 128)
    {
        return Err("invalid initial terminal configuration".into());
    }
    let control = Registration::reserve(&session.id)?;
    crate::ensure_storage_mounted();
    let prepared = crate::storage::prepare_for_run_persistent(image, overlay_id)?;
    let container = crate::resolve_main_container(Some(overlay_id))
        .ok_or("selected image environment has no running container")?;
    let mut env = session.env;
    crate::ssh_agent::inject_into_env(&mut env);
    let launch = crate::ResolvedLaunch::resolve(
        image,
        session
            .builtin
            .as_ref()
            .map(crate::builtin_exec::command)
            .unwrap_or(session.command),
        env,
        session.workdir,
        session.user,
        Vec::new(),
    )?;
    let root = crate::running_container_root(&container).ok_or("container exited before exec")?;
    let identity = crate::oci::resolve_process_identity(&root, launch.user.as_deref())?;
    let environment = crate::oci::process_env_for(&identity, &launch.env);
    let bundle = std::path::Path::new(&prepared.rootfs_path)
        .parent()
        .ok_or("missing image bundle")?
        .join("bundle/config.json");
    let stored: crate::oci::OciSpec = serde_json::from_slice(&std::fs::read(bundle)?)?;
    let mut process = stored.process;
    process.user = identity.user;
    process.cwd = launch.workdir.unwrap_or_else(|| "/".into());
    process.env = crate::crun::augmented_exec_env(&environment, &container)
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    process.terminal = session.terminal.is_some();
    process.console_size = session
        .terminal
        .as_ref()
        .map(|t| crate::oci::OciConsoleSize {
            height: u32::from(t.rows),
            width: u32::from(t.cols),
        });
    let executable = File::open("/proc/self/exe")?;
    let (mut parent, child) = UnixStream::pair()?;
    parent.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    parent.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    process.args = vec![
        format!("/proc/self/fd/{}", executable.as_raw_fd()),
        HELPER.into(),
        executable.as_raw_fd().to_string(),
        child.as_raw_fd().to_string(),
        if session.builtin.is_some() {
            "--builtin"
        } else {
            "--"
        }
        .into(),
    ];
    process.args.extend(launch.command);
    let spec = crate::write_exec_process_file(&container, &process)?;
    let console = if process.terminal {
        Some(crate::pty::ConsoleSocket::bind(&container)?)
    } else {
        None
    };
    let builder = match &console {
        Some(console) => {
            crate::crun::CrunCommand::exec_with_process_console(&container, &spec, console.path())
        }
        None => crate::crun::CrunCommand::exec_with_process(&container, &spec)
            .stdin_piped()
            .capture_output(),
    };
    let spawned = builder
        .controlled_exec_fds(executable.into(), child.into())?
        .spawn();
    let mut owned = match spawned {
        Ok(child) => OwnedCommand {
            child,
            control,
            terminate_on_drop: true,
        },
        Err(error) => {
            return Err(error.into());
        }
    };
    let ready = (|| -> Result<_, Box<dyn std::error::Error>> {
        let terminal = console
            .as_ref()
            .map(|c| c.recv_master(HANDSHAKE_TIMEOUT))
            .transpose()?;
        let process = receive_process(&parent)?;
        owned
            .control
            .activate_descriptor(process, terminal.as_ref().map(|t| t.as_raw_fd()))?;
        if let (Some(terminal), Some(settings)) = (&terminal, &session.terminal) {
            terminal.set_window_size(settings.cols, settings.rows)?;
            crate::terminal_modes::apply(terminal.as_raw_fd(), &settings.modes)?;
        }
        if crate::process::is_peer_closed(stream.as_raw_fd()) {
            return Err("exec canceled before start".into());
        }
        parent.write_all(b"G")?;
        Ok(terminal)
    })();
    drop(spec);
    let terminal = ready?;
    crate::send_response(stream, &AgentResponse::Started)?;
    let result = match terminal {
        Some(terminal) => {
            crate::process::drain_in_background(owned.child.stderr.take());
            crate::run_interactive_loop_pty_controlled(
                stream,
                &mut owned.child,
                terminal,
                session.timeout_ms,
                Some(&owned.control),
            )
        }
        None => crate::run_interactive_loop_controlled(
            stream,
            &mut owned.child,
            session.timeout_ms,
            Some(&owned.control),
        ),
    };
    // A normally completed command may deliberately leave a detached server
    // running (remote editors do this). Disconnects and timeouts have already
    // terminated the group in the I/O loop; other errors retain the drop guard.
    if result.is_ok() {
        owned.terminate_on_drop = false;
    }
    drop(owned);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_descriptor_is_owned_and_close_on_exec() {
        let (parent, child) = UnixStream::pair().unwrap();
        let source = File::open("/dev/null").unwrap();
        sendmsg::<()>(
            child.as_raw_fd(),
            &[IoSlice::new(b"P")],
            &[ControlMessage::ScmRights(&[source.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        let received = receive_process(&parent).unwrap();
        drop(source);
        // A fresh owned descriptor must survive closing the sending copy and
        // must not escape into another concurrently spawned guest command.
        let flags = unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
    }

    fn rejected_handshake_releases_all_descriptors(byte: &[u8], count: usize) {
        let (parent, child) = UnixStream::pair().unwrap();
        let mut readers = Vec::new();
        let mut writers = Vec::new();
        for _ in 0..count {
            let (reader, writer) = UnixStream::pair().unwrap();
            reader.set_nonblocking(true).unwrap();
            readers.push(reader);
            writers.push(writer);
        }
        let descriptors: Vec<_> = writers.iter().map(AsRawFd::as_raw_fd).collect();
        sendmsg::<()>(
            child.as_raw_fd(),
            &[IoSlice::new(byte)],
            &[ControlMessage::ScmRights(&descriptors)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        drop(writers);
        assert!(receive_process(&parent).is_err());
        // EOF proves every received copy was closed, including descriptors
        // accompanying a bad payload or a truncated ancillary message.
        for mut reader in readers {
            assert_eq!(reader.read(&mut [0]).unwrap(), 0);
        }
    }

    #[test]
    fn invalid_handshake_payload_does_not_leak_a_descriptor() {
        rejected_handshake_releases_all_descriptors(b"X", 1);
    }

    #[test]
    fn extra_handshake_descriptors_are_all_released() {
        rejected_handshake_releases_all_descriptors(b"P", 2);
    }

    #[test]
    fn truncated_handshake_descriptors_are_all_released() {
        rejected_handshake_releases_all_descriptors(b"P", 16);
    }
}
