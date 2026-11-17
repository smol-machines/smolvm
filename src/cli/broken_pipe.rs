//! Quiet exit when the reader of the CLI's output goes away.
//!
//! Rust ignores SIGPIPE, so `println!` into a closed pipe
//! (`smolvm machine ls | head -1`, or a reader that exits early) panics with
//! "failed printing to stdout: Broken pipe" and exits 101. Restoring the
//! default SIGPIPE disposition for the whole process is not an option: VM
//! processes forked from the CLI inherit it, and so do `serve` and `exec -i`,
//! which must survive a peer closing a pipe. Instead the panic hook recognises
//! that one panic on the thread that called [`run`], stays silent, and lets it
//! unwind so drop guards still run; [`run`] then ends the process the way a C
//! tool would.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::thread::ThreadId;

static BROKEN: AtomicBool = AtomicBool::new(false);
static RUNNER: OnceLock<ThreadId> = OnceLock::new();

/// Install the panic hook. Call once, early in `main`.
pub fn install() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied());
        if RUNNER.get() == Some(&std::thread::current().id()) && message.is_some_and(is_broken_pipe)
        {
            BROKEN.store(true, Ordering::SeqCst);
            return;
        }
        previous(info);
    }));
}

/// Run `body`, and if it panicked because its output pipe closed, exit the way
/// `cat` does: killed by SIGPIPE on Unix, status 1 elsewhere. Any other panic
/// carries on as before.
pub fn run<T>(body: impl FnOnce() -> T) -> T {
    let _ = RUNNER.set(std::thread::current().id());
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_) if BROKEN.load(Ordering::SeqCst) => exit_broken_pipe(),
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

fn exit_broken_pipe() -> ! {
    #[cfg(unix)]
    // SAFETY: restoring a default disposition and raising a signal on
    // ourselves; nothing else runs on this thread afterwards.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        libc::raise(libc::SIGPIPE);
    }
    std::process::exit(if cfg!(unix) { 128 + 13 } else { 1 })
}

/// Whether a panic message is std's report of a print into a closed pipe.
fn is_broken_pipe(message: &str) -> bool {
    let Some(error) = message
        .strip_prefix("failed printing to stdout: ")
        .or_else(|| message.strip_prefix("failed printing to stderr: "))
    else {
        return false;
    };
    // Compare against the OS's own text for the error, so this tracks the
    // platform's wording: EPIPE on Unix; ERROR_NO_DATA and ERROR_BROKEN_PIPE
    // on Windows.
    #[cfg(unix)]
    let codes = [libc::EPIPE];
    #[cfg(windows)]
    let codes = [232, 109];
    codes
        .iter()
        .any(|&code| error == std::io::Error::from_raw_os_error(code).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_print_into_a_closed_pipe_matches() {
        let epipe = std::io::Error::from(std::io::ErrorKind::BrokenPipe);
        let os = std::io::Error::from_raw_os_error(if cfg!(unix) { libc::EPIPE } else { 232 });
        assert!(is_broken_pipe(&format!("failed printing to stdout: {os}")));
        assert!(is_broken_pipe(&format!("failed printing to stderr: {os}")));
        // A full disk or any other write error still panics loudly.
        let enospc = std::io::Error::from_raw_os_error(if cfg!(unix) { libc::ENOSPC } else { 112 });
        assert!(!is_broken_pipe(&format!(
            "failed printing to stdout: {enospc}"
        )));
        assert!(!is_broken_pipe(&format!("something else: {os}")));
        assert!(!is_broken_pipe(&epipe.to_string()));
    }

    #[cfg(unix)]
    const CHILD: &str = "SMOLVM_BROKEN_PIPE_TEST_CHILD";

    /// The child half of the test below: points stdout at a pipe whose
    /// reader is already closed, then prints.
    #[cfg(unix)]
    #[test]
    fn prints_into_a_closed_pipe() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        let mut fds = [0; 2];
        // SAFETY: plain fd juggling in a child process that only prints next.
        unsafe {
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
            libc::close(fds[0]);
            assert!(libc::dup2(fds[1], libc::STDOUT_FILENO) >= 0);
        }
        install();
        run(|| println!("a line nobody reads"))
    }

    /// Runs the real `println!` into a closed pipe, so a change to std's
    /// panic message shows up here rather than as the panic coming back.
    #[cfg(unix)]
    #[test]
    fn a_closed_pipe_ends_the_process_without_a_panic() {
        use std::os::unix::process::ExitStatusExt;
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cli::broken_pipe::tests::prints_into_a_closed_pipe",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::null())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("panicked"), "{stderr}");
        assert_eq!(output.status.signal(), Some(libc::SIGPIPE), "{stderr}");
    }
}
