//! Create a named container from a selected local image, then start that exact ID.
use crate::{docker::docker_command, runtime::capture};
use std::{collections::HashSet, io::Write, path::Path, sync::atomic::AtomicBool, time::Duration};

#[derive(Clone, Debug)]
pub struct Image {
    pub id: String,
    pub label: String,
}
#[derive(Clone, Debug, Default)]
pub struct Port {
    pub host: u16,
    pub container: u16,
    pub udp: bool,
}
#[derive(Clone, Debug, Default)]
pub struct Mount {
    pub host: String,
    pub container: String,
    pub read_only: bool,
}
#[derive(Clone, Debug, Default)]
pub struct Draft {
    pub image: String,
    pub name: String,
    pub command: Vec<String>,
    pub environment: Vec<(String, String)>,
    pub ports: Vec<Port>,
    pub mounts: Vec<Mount>,
}
#[derive(Debug)]
pub struct Created {
    pub id: String,
    pub warning: Option<String>,
}

impl Draft {
    pub fn validate(&self) -> Result<(), String> {
        crate::storage::validate_image_id(&self.image)?;
        crate::storage::validate_volume(&self.name).map_err(|_| "Enter a container name using letters, numbers, dots, underscores or dashes; start with a letter or number.".to_owned())?;
        if self.command.first().is_some_and(|s| s.is_empty())
            || self.command.iter().any(|s| s.contains('\0'))
        {
            return Err(
                "The command needs a non-empty first argument and cannot contain NUL characters."
                    .into(),
            );
        }
        let mut keys = HashSet::new();
        for (key, value) in &self.environment {
            if !key
                .as_bytes()
                .first()
                .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
                || !key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                || key.contains(['=', '\0', '\n', '\r'])
                || key.chars().any(char::is_whitespace)
                || value.contains(['\0', '\n', '\r'])
                || !keys.insert(key)
            {
                return Err("Use unique environment names with letters, numbers and underscores, starting with a letter or underscore, and single-line values.".into());
            }
        }
        let mut ports = HashSet::new();
        for port in &self.ports {
            if port.host == 0 || port.container == 0 || !ports.insert((port.host, port.udp)) {
                return Err(
                    "Ports must be 1–65535; each host port and protocol can be used once.".into(),
                );
            }
        }
        let mut targets = HashSet::new();
        for mount in &self.mounts {
            if !Path::new(&mount.host).is_absolute()
                || !Path::new(&mount.host).is_dir()
                || mount.host.contains(['\0', '\n', '\r'])
            {
                return Err("Choose an existing host folder using its absolute path.".into());
            }
            // Container paths are Linux paths even when Studio is compiled on Windows.
            let parts: Vec<_> = mount
                .container
                .split('/')
                .filter(|part| !part.is_empty() && *part != ".")
                .collect();
            if !mount.container.starts_with('/')
                || parts.is_empty()
                || mount.container.contains(['\0', '\n', '\r'])
                || parts.contains(&"..")
                || !targets.insert(parts.join("/"))
            {
                return Err("Shared folders need distinct absolute container paths other than /, without .. components.".into());
            }
        }
        Ok(())
    }
    fn args(&self, env_file: &Path) -> Vec<String> {
        let mut args = vec![
            "--context".into(),
            "smol".into(),
            "container".into(),
            "create".into(),
            "--pull".into(),
            "never".into(),
            "--name".into(),
            self.name.clone(),
        ];
        if !self.environment.is_empty() {
            args.extend(["--env-file".into(), env_file.to_string_lossy().into_owned()]);
        }
        for port in &self.ports {
            args.extend([
                "--publish".into(),
                format!(
                    "127.0.0.1:{}:{}/{}",
                    port.host,
                    port.container,
                    if port.udp { "udp" } else { "tcp" }
                ),
            ]);
        }
        for mount in &self.mounts {
            args.extend([
                "--mount".into(),
                format!(
                    "type=bind,{},{}{}",
                    csv(&format!("source={}", mount.host)),
                    csv(&format!("target={}", mount.container)),
                    if mount.read_only { ",readonly" } else { "" }
                ),
            ]);
        }
        args.push(self.image.clone());
        args.extend(self.command.clone());
        args
    }
}
fn csv(value: &str) -> String {
    if value.contains([',', '"']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.into()
    }
}
pub fn images(shutdown: &AtomicBool) -> Result<Vec<Image>, String> {
    let bytes = capture(
        docker_command().args([
            "--context",
            "smol",
            "image",
            "ls",
            "--no-trunc",
            "--format",
            "{{json .}}",
        ]),
        Duration::from_secs(20),
        4 * 1024 * 1024,
        shutdown,
    )?;
    let mut images = Vec::<Image>::new();
    for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let v: serde_json::Value =
            serde_json::from_slice(line).map_err(|_| "Docker returned an invalid image list.")?;
        let id = v["ID"]
            .as_str()
            .ok_or("Image ID missing from Docker response.")?;
        crate::storage::validate_image_id(id)?;
        let repo = v["Repository"].as_str().unwrap_or("<none>");
        let tag = v["Tag"].as_str().unwrap_or("<none>");
        let label = if repo == "<none>" {
            format!("Untagged · {}", &id[7..19])
        } else {
            format!("{repo}:{tag}")
        };
        images.push(Image {
            id: id.into(),
            label,
        });
    }
    images.sort_by(|a, b| a.label.cmp(&b.label).then(a.id.cmp(&b.id)));
    let mut seen = HashSet::new();
    images.retain(|image| seen.insert(image.id.clone()));
    Ok(images)
}
pub fn run(draft: &Draft, shutdown: &AtomicBool) -> Result<Created, String> {
    run_with(draft, shutdown, docker_command)
}
fn run_with(
    draft: &Draft,
    shutdown: &AtomicBool,
    docker: impl Fn() -> std::process::Command,
) -> Result<Created, String> {
    draft.validate()?;
    // Values stay out of the process argument list and disappear after create.
    let mut env = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    for (key, value) in &draft.environment {
        writeln!(env, "{key}={value}").map_err(|e| e.to_string())?;
    }
    env.flush().map_err(|e| e.to_string())?;
    let bytes = capture(
        docker().args(draft.args(env.path())),
        Duration::from_secs(600),
        64 * 1024,
        shutdown,
    )
    .map_err(|e| {
        format!(
            "Could not confirm creation of {}. Check Containers before retrying.\n{e}",
            draft.name
        )
    })?;
    let id = String::from_utf8(bytes)
        .map_err(|_| "Docker returned an invalid container ID. Check Containers before retrying.")?
        .trim()
        .to_owned();
    if id.len() != 64 {
        return Err(
            "Docker did not return a full container ID. Check Containers before retrying.".into(),
        );
    }
    crate::docker::validate_container_id(&id)?;
    drop(env);
    let warning = capture(docker().args(["--context", "smol", "container", "start", &id]), Duration::from_secs(600), 64 * 1024, shutdown)
        .err().map(|e| format!("{} was created, but its start could not be confirmed. Inspect this container before trying Start again.\n{e}", draft.name));
    Ok(Created { id, warning })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn draft() -> Draft {
        Draft {
            name: "studio-test".into(),
            image: format!("sha256:{}", "a".repeat(64)),
            ..Default::default()
        }
    }
    #[test]
    fn preserves_argument_boundaries_and_keeps_values_out_of_arguments() {
        let temp = tempfile::tempdir().unwrap();
        let host = temp.path().join("a,\"b folder");
        std::fs::create_dir(&host).unwrap();
        let mut d = draft();
        d.command = vec![
            "printf".into(),
            "%s".into(),
            "$(touch nope); 'quoted'".into(),
        ];
        d.environment
            .push(("TOKEN".into(), "secret=with spaces".into()));
        d.mounts.push(Mount {
            host: host.to_str().unwrap().into(),
            container: "/with,comma".into(),
            read_only: true,
        });
        d.ports.push(Port {
            host: 8080,
            container: 80,
            udp: false,
        });
        d.validate().unwrap();
        let args = d.args(Path::new("/owned/env"));
        assert_eq!(&args[..2], ["--context", "smol"]);
        assert!(args.windows(2).any(|a| a == ["--pull", "never"]));
        assert!(args.iter().any(|a| a == "127.0.0.1:8080:80/tcp"));
        assert!(!args.iter().any(|a| a.contains("secret")));
        assert_eq!(&args[args.len() - 3..], d.command.as_slice());
        assert!(
            args.iter()
                .any(|a| a.contains("\"target=/with,comma\",readonly"))
        );
    }
    #[test]
    fn rejects_ambiguous_inputs_before_creation() {
        let mut d = draft();
        d.name = "--help".into();
        assert!(d.validate().is_err());
        d = draft();
        d.environment = vec![("#IGNORED".into(), "value".into())];
        assert!(d.validate().is_err());
        d.environment = vec![("TOKEN".into(), "a\nb".into())];
        assert!(d.validate().is_err());
        d.environment = vec![("A".into(), "".into()), ("A".into(), "2".into())];
        assert!(d.validate().is_err());
        d = draft();
        d.ports = vec![
            Port {
                host: 8080,
                container: 80,
                udp: false,
            },
            Port {
                host: 8080,
                container: 81,
                udp: false,
            },
        ];
        assert!(d.validate().is_err());
        d.ports[1].udp = true;
        d.validate().unwrap();
        d.mounts.push(Mount {
            host: "/missing/studio-mount".into(),
            container: "/data".into(),
            read_only: false,
        });
        assert!(d.validate().is_err());
    }
    #[test]
    fn container_mount_paths_use_linux_rules_on_every_host() {
        let temp = tempfile::tempdir().unwrap();
        let mut d = draft();
        let mount = |target: &str| Mount {
            host: temp.path().to_str().unwrap().into(),
            container: target.into(),
            read_only: false,
        };
        d.mounts = vec![mount("/data")];
        d.validate().unwrap();
        for target in ["//", "/.", "/a/../b", "relative", "C:\\data"] {
            d.mounts = vec![mount(target)];
            assert!(d.validate().is_err(), "{target}");
        }
        d.mounts = vec![mount("/data"), mount("//data/./")];
        assert!(d.validate().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn failed_start_returns_created_id_and_removes_temporary_environment() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("docker");
        std::fs::write(
            &script,
            r#"#!/bin/sh
[ "$1 $2" = '--context smol' ] || exit 9
if [ "$3 $4" = 'container create' ]; then
  shift 4
  while [ "$#" -gt 0 ]; do
    if [ "$1" = '--env-file' ]; then
      shift
      printf '%s' "$1" > "$STUDIO_TEST_CAPTURE"
      [ "$(cat "$1")" = 'TOKEN=a=b with spaces' ] || exit 10
    fi
    shift
  done
  printf '%064d\n' 1
elif [ "$3 $4" = 'container start' ]; then
  [ "$5" = '0000000000000000000000000000000000000000000000000000000000000001' ] || exit 11
  echo 'owned fixture cannot start' >&2
  exit 1
else exit 12; fi
"#,
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = root.path().join("env-path");
        let mut d = draft();
        d.environment
            .push(("TOKEN".into(), "a=b with spaces".into()));
        let created = run_with(&d, &AtomicBool::new(false), || {
            let mut c = std::process::Command::new(&script);
            c.env("STUDIO_TEST_CAPTURE", &path);
            c
        })
        .unwrap();
        assert_eq!(created.id, format!("{:064}", 1));
        assert!(
            created
                .warning
                .unwrap()
                .contains("owned fixture cannot start")
        );
        assert!(!Path::new(&std::fs::read_to_string(path).unwrap()).exists());
    }

    #[test]
    #[ignore = "creates explicitly owned containers in an isolated smol context"]
    fn live_run_container_configuration_and_name_conflict() {
        let image = std::env::var("SMOL_STUDIO_RUN_IMAGE").expect("owned local image ID");
        let root =
            std::path::PathBuf::from(std::env::var_os("SMOL_STUDIO_RUN_ROOT").expect("owned root"));
        let name = std::env::var("SMOL_STUDIO_RUN_NAME").expect("owned name");
        let shutdown = AtomicBool::new(false);
        let mount = root.join("mount, with space");
        std::fs::create_dir_all(&mount).unwrap();
        std::fs::write(mount.join("index.html"), "studio-run-ok").unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let d=Draft {image:image.clone(),name:name.clone(),command:vec!["sh".into(),"-c".into(),"test \"$STUDIO_VALUE\" = 'a=b with spaces' || exit 71; if touch /input/should-not-exist 2>/dev/null; then exit 72; fi; exec httpd -f -p 8080 -h /input".into()], environment:vec![("STUDIO_VALUE".into(),"a=b with spaces".into())],ports:vec![Port {host:port,container:8080,udp:false}],mounts:vec![Mount {host:mount.to_str().unwrap().into(),container:"/input".into(),read_only:true}]};
        let created = run(&d, &shutdown).unwrap();
        assert!(created.warning.is_none(), "{:?}", created.warning);
        let result = std::panic::catch_unwind(|| {
            let client = reqwest::blocking::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap();
            let mut body = String::new();
            for _ in 0..50 {
                if let Ok(response) = client.get(format!("http://127.0.0.1:{port}/")).send() {
                    body = response.text().unwrap();
                    if body == "studio-run-ok" {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            assert_eq!(body, "studio-run-ok");
            assert!(!mount.join("should-not-exist").exists());
            let bytes = capture(
                docker_command().args([
                    "--context",
                    "smol",
                    "container",
                    "inspect",
                    "--format",
                    "{{json .}}",
                    &created.id,
                ]),
                Duration::from_secs(20),
                1024 * 1024,
                &shutdown,
            )
            .unwrap();
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(v["Image"], image);
            assert_eq!(v["Config"]["Cmd"], serde_json::json!(d.command));
            assert!(run(&d, &shutdown).is_err());
            let ids = capture(
                docker_command().args([
                    "--context",
                    "smol",
                    "ps",
                    "-aq",
                    "--no-trunc",
                    "--filter",
                    &format!("name=^{name}$"),
                ]),
                Duration::from_secs(20),
                4096,
                &shutdown,
            )
            .unwrap();
            assert_eq!(String::from_utf8(ids).unwrap().trim(), created.id);
        });
        capture(
            docker_command().args([
                "--context",
                "smol",
                "container",
                "stop",
                "--time",
                "1",
                &created.id,
            ]),
            Duration::from_secs(30),
            4096,
            &shutdown,
        )
        .unwrap();
        capture(
            docker_command().args(["--context", "smol", "container", "rm", &created.id]),
            Duration::from_secs(20),
            4096,
            &shutdown,
        )
        .unwrap();
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }
}
