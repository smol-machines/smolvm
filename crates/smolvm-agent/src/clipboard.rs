//! Guest clipboard commands bridged to the host clipboard (on unless
//! `--no-clipboard`).
//!
//! With the bridge on, the agent binary stands in for the usual clipboard
//! commands: it is bind-mounted into the workload container (and linked in a
//! bare VM) as `pbcopy`, `pbpaste`, `xclip`, `xsel`, `wl-copy` and `wl-paste`,
//! and invoked under one of those names it makes one request to the host over
//! [`ports::CLIPBOARD`] (see [`smolvm_protocol::clipboard`]). A program that
//! copies with any of them lands on the host clipboard, and one that pastes,
//! images included, reads it.

#[cfg(test)]
use smolvm_protocol::clipboard::PNG;
use smolvm_protocol::clipboard::{Request, MAX_BYTES, TEXT};
use smolvm_protocol::{guest_env, ports};
use std::io::{self, BufRead, Read, Write};
use std::path::Path;

const AGENT_BINARY: &str = "/usr/local/bin/smolvm-agent";
const HELPER_DIR: &str = "/usr/local/bin";
const NAMES: [&str; 6] = ["pbcopy", "pbpaste", "xclip", "xsel", "wl-copy", "wl-paste"];

/// Whether the host enabled the bridge for this launch.
pub fn is_enabled() -> bool {
    std::env::var(guest_env::CLIPBOARD).as_deref() == Ok(guest_env::VALUE_ON)
}

/// Mount the clipboard commands into a workload container's spec.
pub fn inject_into_container(spec: &mut crate::oci::OciSpec) {
    if !is_enabled() || !Path::new(AGENT_BINARY).is_file() {
        return;
    }
    for name in NAMES {
        spec.add_bind_mount(AGENT_BINARY, &format!("{HELPER_DIR}/{name}"), true);
    }
}

/// Link the clipboard commands in the VM itself, for machines with no image,
/// leaving any command the VM already has.
pub fn install_bare_vm_helpers() {
    if !is_enabled() {
        return;
    }
    for name in NAMES {
        let path = format!("{HELPER_DIR}/{name}");
        if !Path::new(&path).exists() {
            if let Err(error) = std::os::unix::fs::symlink(AGENT_BINARY, &path) {
                tracing::warn!(%error, path, "failed to link clipboard command");
            }
        }
    }
}

/// Whether this invocation is one of the clipboard commands.
pub fn helper_requested() -> bool {
    std::env::args_os()
        .next()
        .and_then(|argv0| {
            Path::new(&argv0)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .is_some_and(|name| NAMES.contains(&name.as_str()))
}

/// Run the clipboard command this binary was invoked as; the exit code.
pub fn run_helper() -> i32 {
    let mut args = std::env::args();
    let argv0 = args.next().unwrap_or_default();
    let name = Path::new(&argv0)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let rest: Vec<String> = args.collect();
    let stdin_is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;
    let command = match parse(&name, &rest, stdin_is_tty) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{name}: {message}");
            return 2;
        }
    };
    match run(&command) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{name}: {error}");
            1
        }
    }
}

/// What one invocation does.
#[derive(Debug, PartialEq, Eq)]
struct Command {
    request: Request,
    /// Content to copy given on the command line (`wl-copy TEXT`), else stdin.
    inline: Option<String>,
    /// Print the type list the way `xclip -t TARGETS -o` does.
    x11_targets: bool,
    /// Drop one trailing newline from pasted text (`wl-paste -n`).
    no_newline: bool,
}

fn parse(name: &str, args: &[String], stdin_is_tty: bool) -> Result<Command, String> {
    let mime = |target: &str| -> String {
        match target {
            "UTF8_STRING" | "STRING" | "TEXT" | "text/plain;charset=utf-8" => TEXT.to_string(),
            other => other.to_string(),
        }
    };
    let mut command = Command {
        request: Request::Paste(TEXT.into()),
        inline: None,
        x11_targets: false,
        no_newline: false,
    };
    match name {
        "pbcopy" => command.request = Request::Copy(TEXT.into()),
        "pbpaste" => {}
        "xclip" => {
            let (mut out, mut target) = (false, TEXT.to_string());
            let mut it = args.iter();
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "-o" | "-out" => out = true,
                    "-i" | "-in" => out = false,
                    "-t" | "-target" => target = mime(it.next().ok_or("-t needs a type")?),
                    "-selection" | "-sel" | "-display" | "-loops" | "-l" => {
                        it.next();
                    }
                    _ => {}
                }
            }
            command.request = match (out, target.as_str()) {
                (true, "TARGETS") => {
                    command.x11_targets = true;
                    Request::Types
                }
                (true, _) => Request::Paste(target),
                (false, _) => Request::Copy(target),
            };
        }
        "xsel" => {
            let output = args.iter().any(|a| a == "-o" || a == "--output");
            let input = args.iter().any(|a| a == "-i" || a == "--input");
            command.request = if output || (!input && stdin_is_tty) {
                Request::Paste(TEXT.into())
            } else {
                Request::Copy(TEXT.into())
            };
        }
        "wl-copy" => {
            let mut target = TEXT.to_string();
            let mut words = Vec::new();
            let mut it = args.iter();
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "-t" | "--type" => target = mime(it.next().ok_or("--type needs a type")?),
                    flag if flag.starts_with('-') => {}
                    word => words.push(word.to_string()),
                }
            }
            command.request = Request::Copy(target);
            command.inline = (!words.is_empty()).then(|| words.join(" "));
        }
        "wl-paste" => {
            let mut it = args.iter();
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "-l" | "--list-types" => command.request = Request::Types,
                    "-n" | "--no-newline" => command.no_newline = true,
                    "-t" | "--type" => {
                        command.request =
                            Request::Paste(mime(it.next().ok_or("--type needs a type")?))
                    }
                    _ => {}
                }
            }
        }
        other => return Err(format!("not a clipboard command: {other}")),
    }
    Ok(command)
}

fn run(command: &Command) -> io::Result<()> {
    let mut host = crate::vsock::connect(ports::CLIPBOARD).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "the host clipboard is unreachable ({error}); start the machine with --clipboard"
            ),
        )
    })?;
    host.write_all(command.request.line().as_bytes())?;
    if let Request::Copy(_) = command.request {
        match &command.inline {
            Some(text) => host.write_all(text.as_bytes())?,
            None => {
                io::copy(&mut io::stdin().lock().take(MAX_BYTES), &mut host)?;
            }
        }
        // SAFETY: the fd is the open vsock stream owned by `host`.
        unsafe { libc::shutdown(std::os::unix::io::AsRawFd::as_raw_fd(&host), libc::SHUT_WR) };
    }
    let mut reader = io::BufReader::new(host);
    let mut status = String::new();
    reader.read_line(&mut status)?;
    if let Some(reason) = status.trim_end().strip_prefix("error: ") {
        return Err(io::Error::other(reason.to_string()));
    }
    if status.trim_end() != "ok" {
        return Err(io::Error::other("the host clipboard gave no answer"));
    }
    let mut body = Vec::new();
    reader.take(MAX_BYTES).read_to_end(&mut body)?;
    if command.x11_targets {
        body = x11_targets(&body);
    }
    if command.no_newline && body.last() == Some(&b'\n') {
        body.pop();
    }
    io::stdout().lock().write_all(&body)
}

/// `xclip -t TARGETS -o` lists X11 atoms; text is advertised under the names
/// X11 programs ask for, and every other type as itself.
fn x11_targets(types: &[u8]) -> Vec<u8> {
    let mut out = String::from("TARGETS\n");
    for mime in String::from_utf8_lossy(types).lines() {
        if mime == TEXT {
            out.push_str("UTF8_STRING\nSTRING\nTEXT\ntext/plain\n");
        } else if !mime.is_empty() {
            out.push_str(mime);
            out.push('\n');
        }
    }
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn each_command_maps_to_its_request() {
        let p = |name: &str, list: &[&str], tty: bool| parse(name, &args(list), tty).unwrap();
        assert_eq!(p("pbcopy", &[], false).request, Request::Copy(TEXT.into()));
        assert_eq!(p("pbpaste", &[], true).request, Request::Paste(TEXT.into()));
        assert_eq!(
            p("xclip", &["-selection", "clipboard"], false).request,
            Request::Copy(TEXT.into())
        );
        let targets = p(
            "xclip",
            &["-selection", "clipboard", "-t", "TARGETS", "-o"],
            true,
        );
        assert!(targets.x11_targets && targets.request == Request::Types);
        assert_eq!(
            p(
                "xclip",
                &["-selection", "clipboard", "-t", "image/png", "-o"],
                true
            )
            .request,
            Request::Paste(PNG.into())
        );
        assert_eq!(
            p("xsel", &["--clipboard", "--output"], false).request,
            Request::Paste(TEXT.into())
        );
        assert_eq!(
            p("xsel", &["-b"], false).request,
            Request::Copy(TEXT.into())
        );
        let inline = p("wl-copy", &["hello", "there"], true);
        assert_eq!(inline.request, Request::Copy(TEXT.into()));
        assert_eq!(inline.inline.as_deref(), Some("hello there"));
        assert_eq!(
            p("wl-paste", &["--list-types"], true).request,
            Request::Types
        );
        let image = p("wl-paste", &["--type", "image/png", "-n"], true);
        assert_eq!(image.request, Request::Paste(PNG.into()));
        assert!(image.no_newline);
        assert!(parse("xclip", &args(&["-t"]), true).is_err());
    }

    #[test]
    fn x11_targets_name_text_the_way_x11_programs_ask() {
        let listed = String::from_utf8(x11_targets(b"text/plain\nimage/png\n")).unwrap();
        assert!(listed.starts_with("TARGETS\n"));
        assert!(listed.contains("UTF8_STRING\n") && listed.contains("image/png\n"));
    }
}
