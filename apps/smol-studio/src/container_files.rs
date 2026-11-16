//! Container files use the same explicit Smol context as the container workspace.
use crate::{
    docker::Output,
    files::{Listing, Request},
    runtime::{capture, find_tool},
};
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::AtomicBool,
    time::Duration,
};

fn socket(shutdown: &AtomicBool) -> Result<PathBuf, String> {
    let connection = crate::docker_connection::check(shutdown);
    if connection.state != crate::docker_connection::State::Ready {
        return Err(connection
            .detail
            .clone()
            .unwrap_or_else(|| connection.description().into()));
    }
    let path = connection
        .endpoint
        .as_deref()
        .and_then(|p| p.strip_prefix("unix://"))
        .filter(|p| p.starts_with('/') && !p.contains('\0'))
        .ok_or("Container files require the local Smol engine connection.")?;
    Ok(path.into())
}

fn regular_file(path: &Path) -> Result<std::fs::Metadata, String> {
    let metadata = path
        .symlink_metadata()
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err("Choose a regular file; folders and symbolic links are not supported for this transfer.".into());
    }
    Ok(metadata)
}

pub(crate) fn execute(request: &Request, shutdown: &AtomicBool) -> Result<Output, String> {
    let id = request.target();
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Choose a container with a complete ID.".into());
    }
    let socket = socket(shutdown)?;
    match request {
        Request::List { path, .. } => {
            crate::files::validate_path(path)?;
            let mut command = Command::new(find_tool(if cfg!(windows) {
                "smolvm.exe"
            } else {
                "smolvm"
            }));
            command
                .args(["engine", "files", "--socket"])
                .arg(socket)
                .args(["--container", id, "list", path, "--json"])
                .env("NO_COLOR", "1")
                .env("RUST_LOG", "error");
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x0800_0000);
            }
            let bytes = capture(
                &mut command,
                Duration::from_secs(75),
                8 * 1024 * 1024,
                shutdown,
            )?;
            let value: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|e| format!("Cannot read this folder: {e}"))?;
            if value["id"].as_str() != Some(id) {
                return Err("The engine returned files from a different container.".into());
            }
            let listing = Listing::parse(&bytes, path)?;
            Ok(Output::Files {
                id: id.into(),
                listing,
            })
        }
        Request::Transfer {
            guest,
            local,
            upload,
            ..
        } => {
            crate::files::validate_path(guest)?;
            if !local.is_absolute() {
                return Err("Choose an absolute local file path.".into());
            }
            let remote = format!("{id}:{guest}");
            let mut command = crate::docker::docker_command();
            command.args(["--context", "smol", "cp"]);
            if *upload {
                // The engine's archive limit includes tar headers, not just file bytes.
                if regular_file(local)?.len() > (4_u64 << 30) - (1 << 20) {
                    return Err("This file is too large. Choose a file smaller than 4 GiB.".into());
                }
                command.arg(local).arg(&remote);
                capture(
                    &mut command,
                    Duration::from_secs(600),
                    1024 * 1024,
                    shutdown,
                )?;
            } else {
                // A failed or interrupted copy must leave the selected destination intact.
                match local.symlink_metadata() {
                    Ok(_) => {
                        regular_file(local)?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(format!("Cannot access {}: {e}", local.display())),
                }
                let parent = local
                    .parent()
                    .ok_or("Choose a file in an existing folder.")?;
                let temporary = tempfile::NamedTempFile::new_in(parent)
                    .map_err(|e| format!("Cannot save in {}: {e}", parent.display()))?;
                command.arg(&remote).arg(temporary.path());
                capture(
                    &mut command,
                    Duration::from_secs(600),
                    1024 * 1024,
                    shutdown,
                )?;
                regular_file(temporary.path())?;
                temporary
                    .persist(local)
                    .map_err(|e| format!("Cannot replace {}: {}", local.display(), e.error))?;
            }
            Ok(Output::FileTransferred {
                id: id.into(),
                local: local.clone(),
                upload: *upload,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires an isolated Smol engine, owned read-only container and writable /app"]
    fn live_container_files_preserve_names_state_and_failed_downloads() {
        let id = std::env::var("SMOL_STUDIO_FILES_CONTAINER").expect("owned container ID");
        let stop = AtomicBool::new(false);
        let inspect = || {
            let mut command = crate::docker::docker_command();
            command.args([
                "--context",
                "smol",
                "inspect",
                "--format",
                "{{json .State}}",
                &id,
            ]);
            capture(&mut command, Duration::from_secs(30), 1024 * 1024, &stop).unwrap()
        };
        let before = inspect();
        let local = tempfile::tempdir().unwrap();
        let name = "a ; $(false) &?#+%\n雪.txt";
        let input = local.path().join(name);
        let content = b"Studio file transfer\0\xff\n";
        std::fs::write(&input, content).unwrap();
        let guest = format!("/app/{name}");
        let transfer = |guest: &str, local: &Path, upload| {
            execute(
                &Request::Transfer {
                    target: id.clone(),
                    guest: guest.into(),
                    local: local.into(),
                    upload,
                },
                &stop,
            )
        };
        assert!(transfer("/tmp/readonly-test.txt", &input, true).is_err());
        transfer(&guest, &input, true).unwrap();
        let Output::Files { listing, .. } = execute(
            &Request::List {
                target: id.clone(),
                path: "/app".into(),
            },
            &stop,
        )
        .unwrap() else {
            panic!("expected folder listing")
        };
        assert!(
            listing
                .entries
                .iter()
                .any(|entry| entry.name == name && entry.size == content.len() as u64)
        );
        let output = local.path().join("existing destination.txt");
        std::fs::write(&output, b"previous contents").unwrap();
        assert!(transfer("/app/missing-file", &output, false).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), b"previous contents");
        transfer(&guest, &output, false).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), content);
        assert!(transfer("/app/missing-parent/file", &input, true).is_err());
        #[cfg(unix)]
        {
            let link = local.path().join("symlink-destination");
            std::os::unix::fs::symlink(&output, &link).unwrap();
            assert!(transfer(&guest, &link, false).is_err());
            assert_eq!(std::fs::read(&output).unwrap(), content);
        }
        assert_eq!(
            inspect(),
            before,
            "file access changed container lifecycle state"
        );
        assert_eq!(
            std::fs::read_dir(local.path()).unwrap().count(),
            if cfg!(unix) { 3 } else { 2 },
            "temporary download leaked"
        );
    }
}
