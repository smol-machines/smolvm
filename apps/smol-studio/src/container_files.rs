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

mod folder_download;

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
        Request::SaveFolder { guest, local, .. } => {
            crate::files::validate_path(guest)?;
            folder_download::download(&format!("{id}:{guest}"), local, shutdown)?;
            Ok(Output::FileTransferred {
                id: id.into(),
                local: local.clone(),
                upload: false,
            })
        }
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

    fn wait_for_shared_folder(id: &str, name: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let result = execute(
                &Request::List {
                    target: id.into(),
                    path: "/app".into(),
                },
                &AtomicBool::new(false),
            );
            if matches!(result, Ok(Output::Files { listing, .. }) if listing.entries.iter().any(|e| e.name == name))
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "host-created fixture folder did not become visible in the guest"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    #[ignore = "requires an isolated Smol container with SMOL_STUDIO_FILES_SHARED mounted at /app"]
    #[cfg(unix)]
    fn live_container_folder_preserves_tree_links_modes_and_state() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let id = std::env::var("SMOL_STUDIO_FILES_CONTAINER").unwrap();
        let shared = PathBuf::from(std::env::var("SMOL_STUDIO_FILES_SHARED").unwrap());
        let source = tempfile::Builder::new()
            .prefix("folder 雪 ; ")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(shared)
            .unwrap();
        let name = source.path().file_name().unwrap().to_str().unwrap();
        let guest = format!("/app/{name}");
        std::fs::create_dir(source.path().join("empty")).unwrap();
        std::fs::create_dir(source.path().join("nested")).unwrap();
        std::fs::write(source.path().join("nested/雪\n.txt"), b"bytes\0\xff").unwrap();
        std::fs::write(source.path().join(".hidden"), b"hidden").unwrap();
        let mut sparse = std::fs::File::create(source.path().join("sparse.bin")).unwrap();
        use std::io::{Seek, Write};
        sparse.set_len(32768).unwrap();
        sparse.seek(std::io::SeekFrom::Start(8192)).unwrap();
        sparse.write_all(b"abc").unwrap();
        drop(sparse);
        std::fs::write(source.path().join("run"), b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            source.path().join("run"),
            std::fs::Permissions::from_mode(0o751),
        )
        .unwrap();
        symlink("nested/雪\n.txt", source.path().join("relative-link")).unwrap();
        symlink("/outside/missing", source.path().join("absolute-link")).unwrap();
        wait_for_shared_folder(&id, name);
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
        let output = local.path().join("renamed copy 雪");
        let save = |guest: &str, path: &Path| {
            execute(
                &Request::SaveFolder {
                    target: id.clone(),
                    guest: guest.into(),
                    local: path.into(),
                },
                &stop,
            )
        };
        save(&guest, &output).unwrap();
        assert_eq!(
            output.metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
        let mut expected_sparse = vec![0; 32768];
        expected_sparse[8192..8195].copy_from_slice(b"abc");
        assert_eq!(
            std::fs::read(output.join("sparse.bin")).unwrap(),
            expected_sparse
        );
        assert_eq!(
            std::fs::read(output.join("nested/雪\n.txt")).unwrap(),
            b"bytes\0\xff"
        );
        assert_eq!(std::fs::read(output.join(".hidden")).unwrap(), b"hidden");
        assert!(output.join("empty").is_dir());
        assert_eq!(
            std::fs::read_link(output.join("relative-link")).unwrap(),
            Path::new("nested/雪\n.txt")
        );
        assert_eq!(
            std::fs::read_link(output.join("absolute-link")).unwrap(),
            Path::new("/outside/missing")
        );
        assert_eq!(
            output.join("run").metadata().unwrap().permissions().mode() & 0o777,
            0o751
        );
        assert!(
            save(&guest, &output)
                .err()
                .unwrap()
                .contains("already exists")
        );
        let failed = local.path().join("failed");
        assert!(save(&format!("{guest}/missing"), &failed).is_err());
        assert!(save(&format!("{guest}/run"), &failed).is_err());
        assert!(save(&format!("{guest}/relative-link"), &failed).is_err());
        assert!(!failed.exists());
        assert_eq!(
            std::fs::read_dir(local.path()).unwrap().count(),
            1,
            "staging leaked"
        );
        assert_eq!(inspect(), before, "folder copy changed lifecycle state");
    }

    #[test]
    #[ignore = "requires isolated container, writable /app bind, and 512 MiB free space"]
    fn live_container_folder_cancel_removes_partial_download() {
        use std::sync::atomic::Ordering;
        let id = std::env::var("SMOL_STUDIO_FILES_CONTAINER").unwrap();
        let shared = PathBuf::from(std::env::var("SMOL_STUDIO_FILES_SHARED").unwrap());
        let source = tempfile::tempdir_in(shared).unwrap();
        let size = 512 * 1024 * 1024;
        std::fs::File::create(source.path().join("large.bin"))
            .unwrap()
            .set_len(size)
            .unwrap();
        wait_for_shared_folder(&id, source.path().file_name().unwrap().to_str().unwrap());
        let remote = format!(
            "{id}:/app/{}",
            source.path().file_name().unwrap().to_str().unwrap()
        );
        let local = tempfile::tempdir().unwrap();
        let destination = local.path().join("copy");
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let copying = scope.spawn(|| folder_download::download(&remote, &destination, &stop));
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            let partial = loop {
                let partial = std::fs::read_dir(local.path())
                    .unwrap()
                    .flatten()
                    .any(|entry| {
                        entry
                            .path()
                            .join("folder/large.bin")
                            .metadata()
                            .is_ok_and(|m| m.len() > 0)
                    });
                if partial || copying.is_finished() || std::time::Instant::now() > deadline {
                    break partial;
                }
                std::thread::sleep(Duration::from_millis(2));
            };
            stop.store(true, Ordering::Release);
            let result = copying.join().unwrap();
            assert!(
                partial,
                "fixture did not observe a staged in-progress copy: {result:?}"
            );
            assert!(result.is_err());
        });
        assert!(!destination.exists());
        assert_eq!(
            std::fs::read_dir(local.path()).unwrap().count(),
            0,
            "partial folder leaked"
        );
    }

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
