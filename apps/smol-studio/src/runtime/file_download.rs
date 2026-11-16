use super::{ERROR_LIMIT, Runtime, capture};
use crate::model::Operation;
use std::{
    io,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub(super) fn download(
    runtime: &Runtime,
    name: &str,
    guest: &str,
    local: &Path,
    shutdown: &AtomicBool,
) -> Result<(), String> {
    if !local.is_absolute() || local.file_name().is_none() {
        return Err("Choose a file in an existing local folder.".into());
    }
    match local.symlink_metadata() {
        Ok(metadata) if !metadata.is_file() => return Err("Choose a regular file; folders and symbolic links cannot be replaced by this download.".into()),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("Cannot access {}: {error}", local.display())),
    }
    let parent = local.parent().ok_or("Choose a destination folder.")?;
    // Own the CLI's staging too: killing a CLI does not run its TempDir Drop.
    // The final rename stays in Studio so stopping the CLI cannot publish a copy.
    let mut builder = tempfile::Builder::new();
    builder.prefix(".smol-download-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let staging = builder
        .tempdir_in(parent)
        .map_err(|error| format!("Cannot save in {}: {error}", parent.display()))?;
    let payload = staging.path().join("payload");
    let mut command = runtime.command(&Operation::TransferFile {
        name: name.into(),
        guest: guest.into(),
        local: payload.clone(),
        upload: false,
    })?;
    capture(
        &mut command,
        Duration::from_secs(600),
        ERROR_LIMIT,
        shutdown,
    )?;
    if !payload
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.is_file())
    {
        return Err("The runtime did not produce a complete regular file. Your destination was left unchanged.".into());
    }
    if shutdown.load(Ordering::Acquire) {
        return Err("File download stopped.".into());
    }
    std::fs::rename(payload, local)
        .map_err(|error| format!("Cannot save {}: {error}", local.display()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::runtime::{Payload, Worker};
    use std::{os::unix::fs::PermissionsExt, thread, time::Instant};

    #[test]
    fn stopping_a_cli_cleans_nested_staging_and_the_worker_can_retry() {
        let root = tempfile::tempdir().unwrap();
        let destination_dir = root.path().join("downloads");
        std::fs::create_dir(&destination_dir).unwrap();
        let destination = destination_dir.join("result");
        std::fs::write(&destination, b"existing").unwrap();
        let cli = root.path().join("cli");
        std::fs::write(
            &cli,
            r#"#!/bin/sh
base=$(dirname -- "$0")
parent=${8%/*}
case "$7" in
/slow)
  mkdir "$parent/cli-owned-staging" || exit 2
  printf partial > "$parent/cli-owned-staging/payload"
  printf '%s' "$$" > "$base/child-pid"
  exec sleep 30
  ;;
/failure)
  mkdir "$parent/cli-owned-staging" || exit 2
  printf partial > "$parent/cli-owned-staging/payload"
  exit 7
  ;;
/link)
  ln -s "$base/external" "$8"
  ;;
*) printf complete > "$8" ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(root.path().join("external"), b"untouched").unwrap();
        let runtime = Runtime {
            executable: cli,
            state_dir: None,
        };
        let operation = |guest: &str| Operation::TransferFile {
            name: "fixture".into(),
            guest: guest.into(),
            local: destination.clone(),
            upload: false,
        };
        let worker = Worker::new(|| {});
        worker.submit(runtime.clone(), operation("/slow")).unwrap();
        let signal = worker.transfer_cancellation().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let pid: i32 = loop {
            if let Some(pid) = std::fs::read_to_string(root.path().join("child-pid"))
                .ok()
                .and_then(|value| value.parse().ok())
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "fixture did not start");
            thread::sleep(Duration::from_millis(5));
        };
        assert!(worker.submit(runtime.clone(), operation("/good")).is_err());
        signal.store(true, Ordering::Release);
        let done = worker
            .responses
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        assert!(done.cancelled && done.result.is_err());
        // SAFETY: signal 0 only checks whether the owned fixture process exists.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        assert_eq!(std::fs::read(&destination).unwrap(), b"existing");
        assert_eq!(std::fs::read_dir(&destination_dir).unwrap().count(), 1);
        assert!(worker.transfer_cancellation().is_none());
        for guest in ["/failure", "/link"] {
            worker.submit(runtime.clone(), operation(guest)).unwrap();
            let done = worker
                .responses
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            assert!(!done.cancelled && done.result.is_err());
            assert_eq!(std::fs::read(&destination).unwrap(), b"existing");
            assert_eq!(std::fs::read_dir(&destination_dir).unwrap().count(), 1);
            assert_eq!(
                std::fs::read(root.path().join("external")).unwrap(),
                b"untouched"
            );
        }
        worker.submit(runtime, operation("/good")).unwrap();
        signal.store(true, Ordering::Release);
        let done = worker
            .responses
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        assert!(!done.cancelled && matches!(done.result, Ok(Payload::Completed)));
        assert_eq!(std::fs::read(&destination).unwrap(), b"complete");
        assert_eq!(std::fs::read_dir(&destination_dir).unwrap().count(), 1);
    }

    #[test]
    #[ignore = "requires public Smol CLI, working hypervisor and Alpine image access"]
    fn live_machine_transfers_stop_without_changing_files_or_machine_state() {
        use crate::model::NewMachine;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let runtime = Runtime {
            executable: std::env::var_os("SMOL_STUDIO_FILES_CLI").unwrap().into(),
            state_dir: Some(root.path().join("state")),
        };
        let stop = AtomicBool::new(false);
        struct Cleanup(Runtime, String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let stop = AtomicBool::new(false);
                let _ = self.0.execute(&Operation::Stop(self.1.clone()), &stop);
                let _ = self.0.execute(&Operation::Delete(self.1.clone()), &stop);
            }
        }
        for (name, image) in [("stop-bare", ""), ("stop-image", "alpine:3.21")] {
            runtime
                .execute(
                    &Operation::Create(NewMachine {
                        name: name.into(),
                        image: image.into(),
                        cpus: 1,
                        memory_mib: 512,
                        network: !image.is_empty(),
                        ..Default::default()
                    }),
                    &stop,
                )
                .unwrap();
            let cleanup = Cleanup(runtime.clone(), name.into());
            runtime
                .execute(&Operation::Start(name.into()), &stop)
                .unwrap();
            let Payload::Output { text, .. } = runtime.execute(&Operation::Exec { name: name.into(), command: "truncate -s 536870912 /workspace/large.bin; printf complete > /workspace/small.txt; printf original > /workspace/uploaded; printf prepared".into() }, &stop).unwrap() else { panic!("guest output") };
            assert!(text.contains("prepared"), "{text}");
            let local = tempfile::tempdir_in(root.path()).unwrap();
            let destination = local.path().join("download");
            std::fs::write(&destination, b"existing").unwrap();
            let transfer = |guest: &str, path: &Path, upload| Operation::TransferFile {
                name: name.into(),
                guest: guest.into(),
                local: path.into(),
                upload,
            };
            let worker = Worker::new(|| {});
            worker
                .submit(
                    runtime.clone(),
                    transfer("/workspace/large.bin", &destination, false),
                )
                .unwrap();
            let signal = worker.transfer_cancellation().unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let mut pending = vec![local.path().to_path_buf()];
                let mut partial = false;
                while let Some(path) = pending.pop() {
                    for entry in std::fs::read_dir(path).unwrap().flatten() {
                        if entry.path() == destination {
                            continue;
                        }
                        if entry.file_type().unwrap().is_dir() {
                            pending.push(entry.path());
                        } else if entry.metadata().unwrap().len() > 0 {
                            partial = true;
                        }
                    }
                }
                if partial {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "download did not start streaming"
                );
                assert!(
                    worker.responses.try_recv().is_err(),
                    "download completed before Stop"
                );
                thread::sleep(Duration::from_millis(2));
            }
            signal.store(true, Ordering::Release);
            let done = worker
                .responses
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            assert!(done.cancelled && done.result.is_err());
            assert_eq!(std::fs::read(&destination).unwrap(), b"existing");
            assert_eq!(std::fs::read_dir(local.path()).unwrap().count(), 1);
            worker
                .submit(
                    runtime.clone(),
                    transfer("/workspace/small.txt", &destination, false),
                )
                .unwrap();
            signal.store(true, Ordering::Release);
            let done = worker
                .responses
                .recv_timeout(Duration::from_secs(15))
                .unwrap();
            assert!(!done.cancelled && done.result.is_ok());
            assert_eq!(std::fs::read(&destination).unwrap(), b"complete");
            let source = root.path().join("upload.bin");
            std::fs::File::create(&source)
                .unwrap()
                .set_len(512 * 1024 * 1024)
                .unwrap();
            worker
                .submit(
                    runtime.clone(),
                    transfer("/workspace/uploaded", &source, true),
                )
                .unwrap();
            let signal = worker.transfer_cancellation().unwrap();
            let upload_staged = || {
                let Payload::Files { listing, .. } = runtime
                    .execute(
                        &Operation::ListFiles {
                            name: name.into(),
                            path: "/workspace".into(),
                        },
                        &stop,
                    )
                    .unwrap()
                else {
                    panic!("listing")
                };
                listing
                    .entries
                    .iter()
                    .any(|entry| entry.name.contains(".smolvm-upload.") && entry.size > 0)
            };
            if image.is_empty() {
                let deadline = Instant::now() + Duration::from_secs(30);
                while !upload_staged() {
                    assert!(Instant::now() < deadline, "upload did not start streaming");
                    if let Ok(done) = worker.responses.try_recv() {
                        panic!(
                            "upload ended before staging was observed; error: {:?}",
                            done.result.err()
                        );
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            } else {
                // Image uploads stage outside the workload namespace. Check an
                // outstanding upload without claiming to observe that scratch file.
                thread::sleep(Duration::from_millis(50));
                assert!(
                    worker.responses.try_recv().is_err(),
                    "upload ended before Stop"
                );
            }
            signal.store(true, Ordering::Release);
            let done = worker
                .responses
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            assert!(done.cancelled && done.result.is_err());
            let deadline = Instant::now() + Duration::from_secs(5);
            while upload_staged() {
                assert!(Instant::now() < deadline, "guest upload staging leaked");
                thread::sleep(Duration::from_millis(10));
            }
            runtime
                .execute(&transfer("/workspace/uploaded", &destination, false), &stop)
                .unwrap();
            assert_eq!(std::fs::read(&destination).unwrap(), b"original");
            let Payload::Machines(rows) = runtime.execute(&Operation::Refresh, &stop).unwrap()
            else {
                panic!("inventory")
            };
            assert!(
                rows.iter()
                    .any(|machine| machine.name == name && machine.state == "running")
            );
            assert_eq!(std::fs::read_dir(local.path()).unwrap().count(), 1);
            drop(worker);
            drop(cleanup);
        }
    }
}
