//! Host side of the clipboard bridge (on unless `--no-clipboard`).
//!
//! The VM's boot process listens on `clipboard.sock` in the machine's
//! directory; libkrun connects it to each guest connection on
//! [`smolvm_protocol::ports::CLIPBOARD`]. Each connection is one request in
//! [`smolvm_protocol::clipboard`]'s format, answered against this host's
//! clipboard: macOS's pasteboard through `pbcopy`/`pbpaste` (and `osascript`
//! for PNG images), or a Linux desktop's through `wl-copy`/`wl-paste` under
//! Wayland and `xclip` under X11.
//!
//! The bridge is on by default, as in other agent sandboxes: a guest that
//! can paste reads whatever the user last copied, so a machine running code
//! that should not see it is created with `--no-clipboard`.

#[cfg(target_os = "macos")]
use smolvm_protocol::clipboard::PNG;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use smolvm_protocol::clipboard::TEXT;
use smolvm_protocol::clipboard::{Request, MAX_BYTES};
use std::io::{BufRead, Read, Write};
use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::{Command, Stdio};

/// File name of the bridge socket in the machine's directory.
pub const CLIPBOARD_SOCKET: &str = "clipboard.sock";

/// Serve the bridge on `socket` from a background thread, one request per
/// connection. `scratch` is a directory for image transfers.
pub fn serve(socket: &Path, scratch: &Path) {
    let _ = std::fs::remove_file(socket);
    let listener = match crate::platform::uds::UdsListener::bind(socket) {
        Ok(listener) => listener,
        Err(error) => {
            tracing::warn!(%error, "clipboard bridge unavailable");
            return;
        }
    };
    let scratch = scratch.to_path_buf();
    let spawned = std::thread::Builder::new()
        .name("clipboard-bridge".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let scratch = scratch.clone();
                let _ = std::thread::Builder::new()
                    .name("clipboard-request".into())
                    .spawn(move || handle(stream, &scratch));
            }
        });
    if let Err(error) = spawned {
        tracing::warn!(%error, "clipboard bridge thread unavailable");
    }
}

fn handle(stream: crate::platform::uds::UdsStream, scratch: &Path) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    if reader.by_ref().take(256).read_line(&mut line).is_err() {
        return;
    }
    let reply = match Request::parse(line.trim_end()) {
        None => Err("unknown clipboard request".to_string()),
        Some(Request::Copy(mime)) => {
            let mut content = Vec::new();
            match reader.take(MAX_BYTES).read_to_end(&mut content) {
                Ok(_) => host_copy(&mime, &content, scratch).map(|()| Vec::new()),
                Err(error) => Err(error.to_string()),
            }
        }
        Some(Request::Paste(mime)) => host_paste(&mime, scratch),
        Some(Request::Types) => Ok(host_types()
            .iter()
            .flat_map(|mime| format!("{mime}\n").into_bytes())
            .collect()),
    };
    let _ = match reply {
        Ok(body) => writer
            .write_all(b"ok\n")
            .and_then(|()| writer.write_all(&body)),
        Err(reason) => writer.write_all(format!("error: {reason}\n").as_bytes()),
    };
}

/// Run `program` with `args`, feeding `input`, and return its stdout.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run(program: &str, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("{program}: {error}"))?;
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin
            .write_all(input)
            .map_err(|error| format!("{program}: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("{program}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{program} exited with {}", output.status));
    }
    Ok(output.stdout)
}

#[cfg(target_os = "macos")]
fn scratch_file(scratch: &Path) -> std::path::PathBuf {
    scratch.join(format!("clipboard-{}.png", std::process::id()))
}

#[cfg(target_os = "macos")]
fn host_copy(mime: &str, content: &[u8], scratch: &Path) -> Result<(), String> {
    match mime {
        TEXT => run("/usr/bin/pbcopy", &[], Some(content)).map(drop),
        PNG => {
            let file = scratch_file(scratch);
            std::fs::write(&file, content).map_err(|e| e.to_string())?;
            let script = format!(
                "set the clipboard to (read (POSIX file \"{}\") as «class PNGf»)",
                file.display()
            );
            let result = run("/usr/bin/osascript", &["-e", &script], None).map(drop);
            let _ = std::fs::remove_file(&file);
            result
        }
        other => Err(format!(
            "the host clipboard takes text/plain and image/png, not {other}"
        )),
    }
}

#[cfg(target_os = "macos")]
fn host_paste(mime: &str, scratch: &Path) -> Result<Vec<u8>, String> {
    match mime {
        TEXT => run("/usr/bin/pbpaste", &[], None),
        PNG => {
            if !host_types().iter().any(|t| t == PNG) {
                return Err("the host clipboard holds no image".to_string());
            }
            let file = scratch_file(scratch);
            let script = format!(
                "set f to (open for access POSIX file \"{}\" with write permission)\n\
                 set eof f to 0\n\
                 write (the clipboard as «class PNGf») to f\n\
                 close access f",
                file.display()
            );
            let result = run("/usr/bin/osascript", &["-e", &script], None)
                .and_then(|_| std::fs::read(&file).map_err(|e| e.to_string()));
            let _ = std::fs::remove_file(&file);
            result
        }
        other => Err(format!(
            "the host clipboard holds text/plain and image/png, not {other}"
        )),
    }
}

#[cfg(target_os = "macos")]
fn host_types() -> Vec<String> {
    let info = run("/usr/bin/osascript", &["-e", "clipboard info"], None).unwrap_or_default();
    let info = String::from_utf8_lossy(&info);
    let mut types = Vec::new();
    if info.contains("string") || info.contains("utf8") || info.contains("«class utf8»") {
        types.push(TEXT.to_string());
    }
    if info.contains("PNGf") {
        types.push(PNG.to_string());
    }
    types
}

#[cfg(target_os = "linux")]
fn wayland() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some()
}

#[cfg(target_os = "linux")]
fn host_copy(mime: &str, content: &[u8], _scratch: &Path) -> Result<(), String> {
    if wayland() {
        run("wl-copy", &["--type", mime], Some(content)).map(drop)
    } else {
        run(
            "xclip",
            &["-selection", "clipboard", "-t", mime, "-i"],
            Some(content),
        )
        .map(drop)
    }
}

#[cfg(target_os = "linux")]
fn host_paste(mime: &str, _scratch: &Path) -> Result<Vec<u8>, String> {
    if wayland() {
        run("wl-paste", &["--no-newline", "--type", mime], None)
    } else {
        run(
            "xclip",
            &["-selection", "clipboard", "-t", mime, "-o"],
            None,
        )
    }
}

#[cfg(target_os = "linux")]
fn host_types() -> Vec<String> {
    let listed = if wayland() {
        run("wl-paste", &["--list-types"], None)
    } else {
        run(
            "xclip",
            &["-selection", "clipboard", "-t", "TARGETS", "-o"],
            None,
        )
    }
    .unwrap_or_default();
    let mut types = Vec::new();
    for line in String::from_utf8_lossy(&listed).lines() {
        let mime = match line.trim() {
            "UTF8_STRING" | "STRING" | "TEXT" | "text/plain;charset=utf-8" => TEXT,
            other => other,
        };
        if (mime == TEXT || mime.contains('/')) && !types.iter().any(|t| t == mime) {
            types.push(mime.to_string());
        }
    }
    types
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn host_copy(_mime: &str, _content: &[u8], _scratch: &Path) -> Result<(), String> {
    Err("the clipboard bridge is not supported on this host".to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn host_paste(_mime: &str, _scratch: &Path) -> Result<Vec<u8>, String> {
    Err("the clipboard bridge is not supported on this host".to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn host_types() -> Vec<String> {
    Vec::new()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn a_malformed_request_is_refused_without_touching_the_clipboard() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(CLIPBOARD_SOCKET);
        serve(&socket, dir.path());
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream.write_all(b"steal everything\n").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        assert_eq!(reply, "error: unknown clipboard request\n");
    }
}
