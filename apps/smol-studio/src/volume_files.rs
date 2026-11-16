//! Native access to the existing host directory of a local Smol volume.
use crate::{
    docker_connection::{self, State},
    runtime::capture,
};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub fn open_label() -> &'static str {
    if cfg!(target_os = "macos") {
        "Open in Finder"
    } else if cfg!(target_os = "windows") {
        "Open in File Explorer"
    } else {
        "Open folder"
    }
}

fn local_endpoint(endpoint: &str) -> bool {
    if let Some(path) = endpoint.strip_prefix("unix://") {
        return Path::new(path).is_absolute() && !path.contains('\0');
    }
    cfg!(windows) && endpoint.starts_with("npipe:////./pipe/") && !endpoint.contains('\0')
}

pub fn is_local(connection: &docker_connection::Connection) -> bool {
    connection.state == State::Ready && connection.endpoint.as_deref().is_some_and(local_endpoint)
}

fn mountpoint(name: &str, created: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "The engine returned invalid volume details.")?;
    if value["Name"].as_str() != Some(name)
        || created.is_empty()
        || value["CreatedAt"].as_str() != Some(created)
    {
        return Err("This volume changed since it was selected. Refresh the volume list before opening its folder.".into());
    }
    if value["Driver"] != "local" || value["Scope"] != "local" {
        return Err("Opening a folder requires a local Smol volume.".into());
    }
    let path = PathBuf::from(
        value["Mountpoint"]
            .as_str()
            .ok_or("The engine did not report a volume folder.")?,
    );
    if !path.is_absolute() {
        return Err("The engine did not report an absolute volume folder.".into());
    }
    if !path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.is_dir())
    {
        return Err(
            "The volume folder is unavailable on this computer. Refresh its details and try again."
                .into(),
        );
    }
    path.canonicalize()
        .map_err(|error| format!("Cannot access the volume folder: {error}"))
}

pub(crate) fn resolve(name: &str, created: &str, stop: &AtomicBool) -> Result<PathBuf, String> {
    crate::storage::validate_volume(name)?;
    let connection = docker_connection::check(stop);
    if !is_local(&connection) {
        return Err("Opening a volume folder requires a local Smol connection. Check the connection and try again.".into());
    }
    let mut command = crate::docker::docker_command();
    command.args([
        "--context",
        "smol",
        "volume",
        "inspect",
        "--format",
        "{{json .}}",
        name,
    ]);
    let bytes = capture(&mut command, Duration::from_secs(20), 1024 * 1024, stop)?;
    mountpoint(name, created, &bytes)
}

pub fn open(name: &str, created: &str, stop: &AtomicBool) -> Result<PathBuf, String> {
    let path = resolve(name, created, stop)?;
    if stop.load(Ordering::Acquire) {
        return Err("Opening the folder was cancelled.".into());
    }
    open_directory(&path, stop)?;
    Ok(path)
}

#[cfg(target_os = "macos")]
fn open_directory(path: &Path, stop: &AtomicBool) -> Result<(), String> {
    let mut command = std::process::Command::new("/usr/bin/open");
    command.args(["-a", "Finder", "--"]).arg(path);
    capture(&mut command, Duration::from_secs(5), 64 * 1024, stop).map(|_| ())
}

#[cfg(target_os = "linux")]
fn open_directory(path: &Path, stop: &AtomicBool) -> Result<(), String> {
    let mut command = folder_command(path)?;
    capture(&mut command, Duration::from_secs(5), 64 * 1024, stop)
        .map(|_| ())
        .map_err(|error| {
            format!("Your desktop could not open the folder. You can copy its path below.\n{error}")
        })
}

#[cfg(target_os = "linux")]
fn folder_command(path: &Path) -> Result<std::process::Command, String> {
    let uri =
        reqwest::Url::from_directory_path(path).map_err(|_| "Cannot open this folder path.")?;
    // FileManager1 opens the folder in the desktop's existing file manager.
    // Wait only for the D-Bus request, never for the file-manager window to close.
    let mut command = std::process::Command::new("dbus-send");
    command
        .args([
            "--session",
            "--type=method_call",
            "--print-reply",
            "--reply-timeout=3000",
            "--dest=org.freedesktop.FileManager1",
            "/org/freedesktop/FileManager1",
            "org.freedesktop.FileManager1.ShowFolders",
        ])
        .arg(format!("array:string:{}", uri.as_str().replace(',', "%2C")))
        .arg("string:");
    Ok(command)
}

#[cfg(target_os = "windows")]
fn open_directory(path: &Path, _stop: &AtomicBool) -> Result<(), String> {
    use std::{ffi::c_void, os::windows::ffi::OsStrExt};
    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoInitializeEx(reserved: *mut c_void, flags: u32) -> i32;
        fn CoUninitialize();
    }
    #[link(name = "shell32")]
    unsafe extern "system" {
        fn ShellExecuteW(
            window: *mut c_void,
            operation: *const u16,
            file: *const u16,
            parameters: *const u16,
            directory: *const u16,
            show: i32,
        ) -> isize;
    }
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let operation: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
    // SAFETY: NUL-terminated strings stay live during the call; optional pointers
    // are null. Balance COM initialization only when it succeeded on this thread.
    let result = unsafe {
        let initialized = CoInitializeEx(std::ptr::null_mut(), 2 | 4) >= 0;
        let result = ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
        );
        if initialized {
            CoUninitialize();
        }
        result
    };
    if result > 32 {
        Ok(())
    } else {
        Err(format!(
            "File Explorer could not open the volume folder (error {result})."
        ))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn open_directory(_path: &Path, _stop: &AtomicBool) -> Result<(), String> {
    Err("Opening volume folders is not supported on this operating system.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn opening_requires_the_selected_local_volume_and_an_existing_directory() {
        let root = tempfile::tempdir().unwrap();
        let folder = root.path().join("project files, 雪 #1");
        std::fs::create_dir(&folder).unwrap();
        let details = json!({"Name":"project-data", "CreatedAt":"2026-11-15T12:00:00Z", "Driver":"local", "Scope":"local", "Mountpoint":folder});
        let resolve = |v: &serde_json::Value| {
            mountpoint(
                "project-data",
                "2026-11-15T12:00:00Z",
                &serde_json::to_vec(v).unwrap(),
            )
        };
        assert_eq!(resolve(&details).unwrap(), folder.canonicalize().unwrap());
        for (key, value) in [
            ("Name", "different"),
            ("CreatedAt", "2026-11-15T12:00:01Z"),
            ("Driver", "remote"),
            ("Scope", "global"),
            ("Mountpoint", "relative/path"),
        ] {
            let mut wrong = details.clone();
            wrong[key] = value.into();
            assert!(resolve(&wrong).is_err(), "{key}");
        }
        assert!(mountpoint("project-data", "", &serde_json::to_vec(&details).unwrap()).is_err());
        std::fs::remove_dir(&folder).unwrap();
        assert!(resolve(&details).is_err());
        std::fs::write(&folder, "not a directory").unwrap();
        assert!(resolve(&details).is_err());
        #[cfg(unix)]
        {
            std::fs::remove_file(&folder).unwrap();
            std::os::unix::fs::symlink(root.path(), &folder).unwrap();
            assert!(resolve(&details).is_err());
        }
    }

    #[test]
    fn remote_engine_paths_are_never_treated_as_host_paths() {
        for endpoint in [
            "ssh://host",
            "tcp://localhost:2375",
            "tcp://127.0.0.1:2375",
            "unix://relative",
            "unix:///tmp/socket\0other",
            "npipe:////server/pipe/docker",
        ] {
            assert!(!local_endpoint(endpoint), "{endpoint}");
        }
        #[cfg(unix)]
        assert!(local_endpoint("unix:///tmp/smol/docker.sock"));
        #[cfg(windows)]
        assert!(local_endpoint("npipe:////./pipe/smol"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_manager_receives_one_exact_folder_uri() {
        use std::{
            io::{BufRead, BufReader},
            process::{Command, Stdio},
            sync::{Arc, Mutex},
        };
        struct Bus(std::process::Child);
        impl Drop for Bus {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut bus = Bus(Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap());
        let mut address = String::new();
        BufReader::new(bus.0.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        struct Manager(Arc<Mutex<Vec<String>>>);
        #[zbus::interface(name = "org.freedesktop.FileManager1")]
        impl Manager {
            fn show_folders(&self, uris: Vec<String>, startup_id: String) {
                assert!(startup_id.is_empty());
                *self.0.lock().unwrap() = uris;
            }
        }
        let received = Arc::new(Mutex::new(Vec::new()));
        let _server = zbus::blocking::connection::Builder::address(address.trim())
            .unwrap()
            .name("org.freedesktop.FileManager1")
            .unwrap()
            .serve_at("/org/freedesktop/FileManager1", Manager(received.clone()))
            .unwrap()
            .build()
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        let folder = root.path().join("spaces, # 雪\nsecond line");
        std::fs::create_dir(&folder).unwrap();
        let mut command = folder_command(&folder).unwrap();
        command.env("DBUS_SESSION_BUS_ADDRESS", address.trim());
        capture(
            &mut command,
            Duration::from_secs(5),
            65536,
            &AtomicBool::new(false),
        )
        .unwrap();
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(
            reqwest::Url::parse(&received[0])
                .unwrap()
                .to_file_path()
                .unwrap(),
            folder
        );
    }

    #[test]
    #[ignore = "requires an owned local Smol volume; optionally opens its native file manager"]
    fn live_volume_folder_resolves_fresh_identity() {
        let name = std::env::var("SMOL_STUDIO_TEST_VOLUME").unwrap();
        let stop = AtomicBool::new(false);
        let mut inspect = crate::docker::docker_command();
        inspect.args([
            "--context",
            "smol",
            "volume",
            "inspect",
            "--format",
            "{{json .}}",
            &name,
        ]);
        let value: serde_json::Value = serde_json::from_slice(
            &capture(&mut inspect, Duration::from_secs(20), 1024 * 1024, &stop).unwrap(),
        )
        .unwrap();
        let created = value["CreatedAt"].as_str().unwrap();
        let expected = Path::new(value["Mountpoint"].as_str().unwrap())
            .canonicalize()
            .unwrap();
        assert_eq!(resolve(&name, created, &stop).unwrap(), expected);
        assert!(
            resolve(&name, "stale selection", &stop)
                .unwrap_err()
                .contains("changed")
        );
        if std::env::var_os("SMOL_STUDIO_TEST_OPEN_FOLDER").is_some() {
            assert_eq!(open(&name, created, &stop).unwrap(), expected);
        }
    }
}
