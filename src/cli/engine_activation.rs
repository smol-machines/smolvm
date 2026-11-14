//! Install the one Docker entry point: an OS-owned socket and a disposable adapter.
use smolvm::engine::EngineConfig;
use std::path::Path;

fn service_name(config: &EngineConfig) -> String {
    use sha2::{Digest, Sha256};
    let hash = hex::encode(Sha256::digest(config.socket.as_os_str().as_encoded_bytes()));
    format!("smolvm-docker-{}", &hash[..12])
}
fn run(program: &str, args: &[&str]) -> smolvm::Result<()> {
    let output = std::process::Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(smolvm::Error::config(
            "Docker socket activation",
            String::from_utf8_lossy(&output.stderr).trim(),
        ));
    }
    Ok(())
}

pub(super) fn install(config: &EngineConfig) -> smolvm::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let parent = config
        .socket
        .parent()
        .ok_or_else(|| smolvm::Error::config("engine socket", "socket needs a parent directory"))?;
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    std::fs::create_dir_all(&config.root)?;
    if !registered(config) && std::os::unix::net::UnixStream::connect(&config.socket).is_ok() {
        return Err(smolvm::Error::config("Docker socket activation", "the socket is occupied by an existing engine; finish its workloads and stop that engine before registering automatic activation"));
    }
    if config.socket.to_string_lossy().contains(['\n', '\r']) {
        return Err(smolvm::Error::config(
            "engine socket",
            "socket path cannot contain a newline",
        ));
    }
    let exe = std::env::current_exe()?;
    let home =
        dirs::home_dir().ok_or_else(|| smolvm::Error::config("engine", "no home directory"))?;
    let name = service_name(config);
    #[cfg(target_os = "linux")]
    {
        let dir = dirs::config_dir()
            .unwrap_or_else(|| home.join(".config"))
            .join("systemd/user");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(format!("{name}.socket")), systemd_socket(config))?;
        std::fs::write(
            dir.join(format!("{name}.service")),
            systemd_service(config, &exe),
        )?;
        run(
            "systemctl",
            &[
                "--user",
                "link",
                &dir.join(format!("{name}.service")).to_string_lossy(),
            ],
        )?;
        run("systemctl", &["--user", "daemon-reload"])?;
        run(
            "systemctl",
            &[
                "--user",
                "enable",
                "--now",
                &dir.join(format!("{name}.socket")).to_string_lossy(),
            ],
        )?;
    }
    #[cfg(target_os = "macos")]
    {
        let dir = home.join("Library/LaunchAgents");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{name}.plist"));
        let plist = launch_agent(config, &exe, &name);
        let changed = std::fs::read_to_string(&path).ok().as_deref() != Some(&plist);
        std::fs::write(&path, plist)?;
        // Existing workloads are independent; changing the registration never stops them.
        let domain = format!("gui/{}", unsafe { libc::getuid() });
        let registered = std::process::Command::new("launchctl")
            .args(["print", &format!("{domain}/{name}")])
            .output()?
            .status
            .success();
        if registered && changed {
            run("launchctl", &["bootout", &format!("{domain}/{name}")])?;
        }
        if !registered || changed {
            // launchd can leave SockPathName behind after bootout; wait for
            // the former listener to close before replacing that stale node.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while std::os::unix::net::UnixStream::connect(&config.socket).is_ok() {
                if std::time::Instant::now() >= deadline {
                    return Err(smolvm::Error::config(
                        "Docker socket activation",
                        "previous adapter has not released its socket",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            match std::fs::remove_file(&config.socket) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            run(
                "launchctl",
                &["bootstrap", &domain, &path.to_string_lossy()],
            )?;
            use std::os::unix::fs::FileTypeExt;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !std::fs::metadata(&config.socket).is_ok_and(|m| m.file_type().is_socket()) {
                if std::time::Instant::now() >= deadline {
                    return Err(smolvm::Error::config(
                        "Docker socket activation",
                        "launchd did not create the Docker socket",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
    Ok(())
}

pub(super) fn uninstall(config: &EngineConfig) -> smolvm::Result<()> {
    let name = service_name(config);
    let home =
        dirs::home_dir().ok_or_else(|| smolvm::Error::config("engine", "no home directory"))?;
    #[cfg(target_os = "linux")]
    {
        let dir = dirs::config_dir()
            .unwrap_or_else(|| home.join(".config"))
            .join("systemd/user");
        if dir.join(format!("{name}.socket")).exists() {
            run(
                "systemctl",
                &["--user", "disable", "--now", &format!("{name}.socket")],
            )?;
            run("systemctl", &["--user", "stop", &format!("{name}.service")])?;
            std::fs::remove_file(dir.join(format!("{name}.socket")))?;
            std::fs::remove_file(dir.join(format!("{name}.service")))?;
            run("systemctl", &["--user", "daemon-reload"])?;
        }
    }
    #[cfg(target_os = "macos")]
    {
        let path = home
            .join("Library/LaunchAgents")
            .join(format!("{name}.plist"));
        if path.exists() {
            let domain = format!("gui/{}", unsafe { libc::getuid() });
            run("launchctl", &["bootout", &format!("{domain}/{name}")])?;
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

pub(super) fn registered(config: &EngineConfig) -> bool {
    let name = service_name(config);
    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", &format!("{name}.socket")])
        .status();
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("launchctl")
        .args([
            "print",
            &format!("gui/{}/{name}", unsafe { libc::getuid() }),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return false;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    result.is_ok_and(|s| s.success())
}

fn environment() -> Vec<(String, String)> {
    [
        "PATH",
        "SMOLVM_LIB_DIR",
        "SMOLVM_AGENT_ROOTFS",
        "SMOLVM_DATA_DIR",
        "SMOLVM_CONFIG",
    ]
    .into_iter()
    .filter_map(|key| std::env::var(key).ok().map(|value| (key.into(), value)))
    .collect()
}

#[cfg(any(target_os = "linux", test))]
fn unit_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    )
}
#[cfg(any(target_os = "linux", test))]
fn systemd_socket(config: &EngineConfig) -> String {
    format!("[Unit]\nDescription=SmolVM Docker API socket\n[Socket]\nListenStream={}\nSocketMode=0600\nDirectoryMode=0700\nRemoveOnStop=true\n[Install]\nWantedBy=sockets.target\n", config.socket.to_string_lossy().replace('%', "%%"))
}
#[cfg(any(target_os = "linux", test))]
fn systemd_service(config: &EngineConfig, exe: &Path) -> String {
    let args = [
        exe.to_string_lossy().into_owned(),
        "engine".into(),
        "serve".into(),
        "--socket".into(),
        config.socket.to_string_lossy().into_owned(),
        "--root".into(),
        config.root.to_string_lossy().into_owned(),
    ];
    let env = environment()
        .iter()
        .map(|(k, v)| format!("Environment={}\n", unit_quote(&format!("{k}={v}"))))
        .collect::<String>();
    // Supervisors are workload processes, not part of the adapter's stop operation.
    format!("[Unit]\nDescription=SmolVM Docker API adapter\n[Service]\nExecStart={}\nKillMode=process\nTimeoutStopSec=10\nUMask=0077\n{env}", args.iter().map(|s|unit_quote(&s.replace('$', "$$"))).collect::<Vec<_>>().join(" "))
}
#[cfg(any(target_os = "macos", test))]
fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
#[cfg(any(target_os = "macos", test))]
fn launch_agent(config: &EngineConfig, exe: &Path, name: &str) -> String {
    let args = [
        exe.to_string_lossy().into_owned(),
        "engine".into(),
        "serve".into(),
        "--socket".into(),
        config.socket.to_string_lossy().into_owned(),
        "--root".into(),
        config.root.to_string_lossy().into_owned(),
    ];
    let args = args
        .iter()
        .map(|s| format!("<string>{}</string>", xml(s)))
        .collect::<String>();
    let env = environment()
        .iter()
        .map(|(k, v)| format!("<key>{}</key><string>{}</string>", xml(k), xml(v)))
        .collect::<String>();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{}</string>
<key>ProgramArguments</key><array>{args}</array>
<key>EnvironmentVariables</key><dict>{env}</dict>
<key>Sockets</key><dict><key>Docker</key><dict><key>SockPathName</key><string>{}</string><key>SockPathMode</key><integer>384</integer></dict></dict>
<key>AbandonProcessGroup</key><true/>
<key>ThrottleInterval</key><integer>1</integer>
<key>Umask</key><integer>63</integer>
<key>StandardOutPath</key><string>{}</string>
<key>StandardErrorPath</key><string>{}</string>
</dict></plist>
"#,
        xml(name),
        xml(&config.socket.to_string_lossy()),
        xml(&config.root.join("adapter.log").to_string_lossy()),
        xml(&config.root.join("adapter.log").to_string_lossy())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn activation_does_not_start_an_idle_service_or_kill_workloads() {
        let c = EngineConfig {
            socket: "/tmp/smol space/docker.sock".into(),
            root: "/tmp/state".into(),
        };
        assert!(systemd_socket(&c).contains("ListenStream=/tmp/smol space/docker.sock\n"));
        let unit = systemd_service(&c, Path::new("/path with spaces/smolvm"));
        assert!(unit.contains("ExecStart=\"/path with spaces/smolvm\" \"engine\" \"serve\""));
        assert!(unit.contains("KillMode=process"));
        assert!(!unit.contains("Restart=always"));
        let plist = launch_agent(&c, Path::new("/path & other/smolvm"), "test");
        assert!(plist.contains("<key>ThrottleInterval</key><integer>1</integer>"));
        assert!(plist.contains("/path &amp; other/smolvm"));
        assert!(plist.contains("<key>AbandonProcessGroup</key><true/>"));
        assert!(!plist.contains("KeepAlive"));
        assert!(!plist.contains("RunAtLoad"));
    }
    #[test]
    fn systemd_arguments_do_not_expand_specifiers_or_environment() {
        assert_eq!(
            unit_quote("/tmp/%n/$NAME/\"x\"").replace('$', "$$"),
            "\"/tmp/%%n/$$NAME/\\\"x\\\"\""
        );
    }
}
