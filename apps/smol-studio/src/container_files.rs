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
                if shutdown.load(std::sync::atomic::Ordering::Acquire) {
                    return Err("File download stopped.".into());
                }
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
    #[ignore = "requires isolated Smol container, writable /app bind, and 512 MiB free space"]
    fn live_container_transfer_stop_is_scoped_and_reusable() {
        use crate::docker::{Action, DockerWorker};
        use crate::runtime::Runtime;
        use std::sync::atomic::Ordering;
        let id = std::env::var("SMOL_STUDIO_FILES_CONTAINER").unwrap();
        let shared = PathBuf::from(std::env::var("SMOL_STUDIO_FILES_SHARED").unwrap());
        let source = tempfile::tempdir_in(shared).unwrap();
        std::fs::File::create(source.path().join("large.bin"))
            .unwrap()
            .set_len(512 * 1024 * 1024)
            .unwrap();
        std::fs::write(source.path().join("small.txt"), b"retry succeeded").unwrap();
        let name = source.path().file_name().unwrap().to_str().unwrap();
        wait_for_shared_folder(&id, name);
        let guest = format!("/app/{name}");
        let local = tempfile::tempdir().unwrap();
        let destination = local.path().join("download");
        let worker = DockerWorker::new(|| {});
        let runtime = Runtime::discover();
        for folder in [true, false] {
            let request = if folder {
                Request::SaveFolder {
                    target: id.clone(),
                    guest: guest.clone(),
                    local: destination.clone(),
                }
            } else {
                std::fs::write(&destination, b"existing destination").unwrap();
                Request::Transfer {
                    target: id.clone(),
                    guest: format!("{guest}/large.bin"),
                    local: destination.clone(),
                    upload: false,
                }
            };
            worker
                .submit(runtime.clone(), Action::Files(request))
                .unwrap();
            let signal = worker
                .transfer_cancellation()
                .expect("transfer can be stopped");
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                let partial = std::fs::read_dir(local.path())
                    .unwrap()
                    .flatten()
                    .any(|entry| {
                        let path = entry.path();
                        if path == destination {
                            return false;
                        }
                        let payload = if folder {
                            path.join("folder/large.bin")
                        } else {
                            path
                        };
                        payload.metadata().is_ok_and(|m| m.len() > 0)
                    });
                if partial {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "copy did not start streaming"
                );
                assert!(
                    worker.events.try_recv().is_err(),
                    "copy finished before it could be stopped"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            assert!(
                worker.submit(runtime.clone(), Action::Status).is_err(),
                "another job displaced the active transfer"
            );
            let stopped = std::time::Instant::now();
            signal.store(true, Ordering::Release);
            let done = worker.events.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(done.cancelled && done.result.is_err());
            assert!(stopped.elapsed() < Duration::from_secs(5));
            assert!(worker.transfer_cancellation().is_none());
            if folder {
                assert!(!destination.exists());
            } else {
                assert_eq!(
                    std::fs::read(&destination).unwrap(),
                    b"existing destination"
                );
            }
            assert_eq!(
                std::fs::read_dir(local.path()).unwrap().count(),
                usize::from(!folder)
            );
            // Keep signalling the old transfer while the same worker saves a new one.
            worker
                .submit(
                    runtime.clone(),
                    Action::Files(Request::Transfer {
                        target: id.clone(),
                        guest: format!("{guest}/small.txt"),
                        local: destination.clone(),
                        upload: false,
                    }),
                )
                .unwrap();
            signal.store(true, Ordering::Release);
            let done = worker.events.recv_timeout(Duration::from_secs(30)).unwrap();
            assert!(!done.cancelled);
            assert!(matches!(done.result, Ok(Output::FileTransferred { .. })));
            assert_eq!(std::fs::read(&destination).unwrap(), b"retry succeeded");
            std::fs::remove_file(&destination).unwrap();
        }
        worker
            .submit(
                runtime.clone(),
                Action::Files(Request::List {
                    target: id.clone(),
                    path: guest.clone(),
                }),
            )
            .unwrap();
        assert!(
            worker.transfer_cancellation().is_none(),
            "browsing is not an upload or download"
        );
        assert!(
            worker
                .events
                .recv_timeout(Duration::from_secs(30))
                .unwrap()
                .result
                .is_ok()
        );
        // A stop immediately after submission must not be reset when execution begins.
        worker
            .submit(
                runtime,
                Action::Files(Request::SaveFolder {
                    target: id,
                    guest,
                    local: destination.clone(),
                }),
            )
            .unwrap();
        worker
            .transfer_cancellation()
            .unwrap()
            .store(true, Ordering::Release);
        let done = worker.events.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(done.cancelled && done.result.is_err());
        assert!(!destination.exists());
        assert_eq!(std::fs::read_dir(local.path()).unwrap().count(), 0);
    }

    #[test]
    #[ignore = "requires isolated Smol container, writable /app bind, upload cache and 512 MiB free space"]
    fn live_container_upload_stop_and_worker_close_release_resources() {
        use crate::docker::{Action, DockerWorker};
        use crate::runtime::Runtime;
        use std::sync::atomic::Ordering;
        let id = std::env::var("SMOL_STUDIO_FILES_CONTAINER").unwrap();
        let shared = PathBuf::from(std::env::var("SMOL_STUDIO_FILES_SHARED").unwrap());
        let cache = PathBuf::from(std::env::var("SMOL_STUDIO_UPLOAD_CACHE").unwrap());
        let remote = tempfile::tempdir_in(shared).unwrap();
        let name = remote.path().file_name().unwrap().to_str().unwrap();
        let target = remote.path().join("received.bin");
        std::fs::write(&target, b"original destination").unwrap();
        wait_for_shared_folder(&id, name);
        let local = tempfile::tempdir().unwrap();
        let source = local.path().join("large.bin");
        let size = 512 * 1024 * 1024;
        std::fs::File::create(&source)
            .unwrap()
            .set_len(size)
            .unwrap();
        let runtime = Runtime::discover();
        let uploads = || {
            std::fs::read_dir(&cache)
                .unwrap()
                .flatten()
                .map(|entry| entry.path().join("upload.tar"))
                .filter(|p| p.exists())
                .collect::<Vec<_>>()
        };
        assert!(
            uploads().is_empty(),
            "fixture cache has another active upload"
        );
        for close in [false, true] {
            let worker = DockerWorker::new(|| {});
            worker
                .submit(
                    runtime.clone(),
                    Action::Files(Request::Transfer {
                        target: id.clone(),
                        guest: format!("/app/{name}/received.bin"),
                        local: source.clone(),
                        upload: true,
                    }),
                )
                .unwrap();
            let signal = worker.transfer_cancellation().unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                if uploads()
                    .iter()
                    .any(|p| p.metadata().is_ok_and(|m| m.len() > 0 && m.len() < size))
                {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "upload did not start streaming"
                );
                assert!(
                    worker.events.try_recv().is_err(),
                    "upload finished before cancellation"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            let stopped = std::time::Instant::now();
            if close {
                drop(worker);
            } else {
                signal.store(true, Ordering::Release);
                let done = worker.events.recv_timeout(Duration::from_secs(5)).unwrap();
                assert!(done.cancelled && done.result.is_err());
            }
            assert!(stopped.elapsed() < Duration::from_secs(5));
            while !uploads().is_empty() {
                assert!(
                    stopped.elapsed() < Duration::from_secs(5),
                    "server upload staging leaked"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(std::fs::read(&target).unwrap(), b"original destination");
        }
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
