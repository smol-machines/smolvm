use std::{
    io,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub(super) fn download(remote: &str, local: &Path, shutdown: &AtomicBool) -> Result<(), String> {
    if !local.is_absolute() || local.file_name().is_none() {
        return Err("Choose a new folder inside an existing local folder.".into());
    }
    match local.symlink_metadata() {
        Ok(_) => return Err("The destination already exists. Choose a different folder name; existing items are never merged or replaced.".into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("Cannot access {}: {e}", local.display())),
    }
    let parent = local.parent().ok_or("Choose a destination folder.")?;
    let stage = Stage(
        tempfile::Builder::new()
            .prefix(".smol-download-")
            .tempdir_in(parent)
            .map_err(|e| format!("Cannot save in {}: {e}", parent.display()))?,
    );
    let payload = stage.0.path().join("folder");
    let mut command = crate::docker::docker_command();
    command
        .args(["--context", "smol", "cp"])
        .arg(remote)
        .arg(&payload);
    crate::runtime::capture(
        &mut command,
        Duration::from_secs(600),
        1024 * 1024,
        shutdown,
    )?;
    if !payload.symlink_metadata().is_ok_and(|m| m.is_dir()) {
        return Err(
            "The selected path is no longer a folder. Refresh the file list and try again.".into(),
        );
    }
    if shutdown.load(Ordering::Acquire) {
        return Err("Folder download cancelled.".into());
    }
    publish(&payload, local).map_err(|e| {
        format!(
            "Could not save {}: {e}; existing items were not replaced.",
            local.display()
        )
    })
}

// Downloads may contain read-only directories. Make only our private staging
// directories removable on failure; never follow links or modify the published copy.
struct Stage(tempfile::TempDir);
impl Drop for Stage {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut pending = vec![self.0.path().to_path_buf()];
            while let Some(path) = pending.pop() {
                let Ok(metadata) = path.symlink_metadata() else {
                    continue;
                };
                if !metadata.is_dir() {
                    continue;
                }
                let _ = std::fs::set_permissions(
                    &path,
                    std::fs::Permissions::from_mode(metadata.permissions().mode() | 0o700),
                );
                if let Ok(entries) = std::fs::read_dir(&path) {
                    for entry in entries.flatten() {
                        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                            pending.push(entry.path());
                        }
                    }
                }
            }
        }
    }
}

// A check followed by ordinary rename can replace a folder created during the
// download. Use the platform's exclusive rename, on the same filesystem as staging.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn publish(source: &Path, destination: &Path) -> io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let destination = CString::new(destination.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: Both pointers refer to live, NUL-terminated path buffers. The flags
    // forbid replacing any existing destination, including an empty directory.
    let result = unsafe {
        #[cfg(target_os = "linux")]
        {
            libc::renameat2(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        }
        #[cfg(target_os = "macos")]
        {
            libc::renamex_np(source.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL)
        }
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn publish(_source: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Container folder downloads require macOS or Linux.",
    ))
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn publication_preserves_destinations_created_during_download() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("staged");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("data"), b"downloaded").unwrap();
        let destination = root.path().join("destination");
        std::fs::create_dir(&destination).unwrap();
        assert!(publish(&source, &destination).is_err());
        assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0);
        std::fs::remove_dir(&destination).unwrap();
        symlink(&source, &destination).unwrap();
        assert!(publish(&source, &destination).is_err());
        std::fs::remove_file(&destination).unwrap();
        publish(&source, &destination).unwrap();
        assert_eq!(
            std::fs::read(destination.join("data")).unwrap(),
            b"downloaded"
        );
        assert!(!source.exists());
    }

    #[test]
    fn failed_download_cleanup_handles_readonly_folders_without_following_links() {
        let root = tempfile::tempdir().unwrap();
        let outside = root.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep"), b"untouched").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o500)).unwrap();
        let stage = Stage(tempfile::tempdir_in(root.path()).unwrap());
        let path = stage.0.path().to_path_buf();
        let folder = path.join("readonly");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("partial"), b"partial").unwrap();
        symlink(&outside, folder.join("link")).unwrap();
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o000)).unwrap();
        drop(stage);
        assert!(!path.exists());
        assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"untouched");
        assert_eq!(
            outside.metadata().unwrap().permissions().mode() & 0o777,
            0o500
        );
        std::fs::set_permissions(outside, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
