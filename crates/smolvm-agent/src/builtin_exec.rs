//! Agent-owned helpers entered only after applying the workload's identity.
use smolvm_protocol::interactive_control::Builtin;
use std::{ffi::OsString, io};

pub fn command(operation: &Builtin) -> Vec<String> {
    match operation {
        Builtin::Sftp => vec!["sftp-server".into()],
        Builtin::TcpConnect { host, port } => {
            vec!["tcp-forward".into(), host.clone(), port.to_string()]
        }
    }
}

pub fn requested() -> bool {
    matches!(
        std::env::args_os()
            .nth(1)
            .as_deref()
            .and_then(|s| s.to_str()),
        Some("sftp-server" | "tcp-forward")
    )
}

pub fn run_helper() -> i32 {
    match run(&std::env::args_os().skip(1).collect::<Vec<_>>()) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("smolvm guest operation: {error}");
            1
        }
    }
}

pub fn run(args: &[OsString]) -> io::Result<()> {
    match args.first().and_then(|s| s.to_str()) {
        Some("sftp-server") if args.len() == 1 => {
            crate::sftp::serve(&mut io::stdin().lock(), &mut io::stdout().lock())
        }
        Some("tcp-forward") => crate::tcp_forward::run(args),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid guest operation",
        )),
    }
}
