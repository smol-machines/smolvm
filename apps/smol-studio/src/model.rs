use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Machine {
    #[serde(default)]
    pub labels: Option<BTreeMap<String, String>>,
    pub name: String,
    pub state: String,
    pub cpus: u16,
    pub memory_mib: u64,
    #[serde(default)]
    pub storage_gb: Option<u64>,
    #[serde(default)]
    pub overlay_gb: Option<u64>,
    #[serde(default)]
    pub network: Option<bool>,
    #[serde(default)]
    pub shared_folders: Option<Vec<MachineFolder>>,
    #[serde(default)]
    pub port_mappings: Option<Vec<MachinePort>>,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub mounts: usize,
    #[serde(default)]
    pub ports: usize,
    #[serde(default)]
    pub parent_machine: Option<String>,
    #[serde(default)]
    pub state_reason: Option<String>,
}

// Read-only inventory keeps unknown modes/protocols visible instead of rejecting
// a newer CLI's entire list; the settings editor validates editable values.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct MachineFolder {
    pub host: String,
    pub guest: String,
    pub mode: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct MachinePort {
    pub host: u16,
    pub guest: u16,
    pub protocol: String,
}

impl Machine {
    /// Reserved ownership labels come from the engine, not from machine names.
    /// Keep unmarked and unfamiliar machines visible, including older CLI rows.
    fn engine_managed(&self) -> bool {
        let Some(labels) = &self.labels else {
            return false;
        };
        let populated = |key: &str| labels.get(key).is_some_and(|value| !value.is_empty());
        labels
            .get("smolvm.engine/container")
            .is_some_and(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            || populated("smolvm.engine.builder")
            || (populated("smolvm.engine/base") && populated("smolvm.engine/base-engine"))
    }

    pub fn can_start(&self) -> bool {
        matches!(self.state.as_str(), "created" | "stopped" | "failed")
    }

    pub fn can_stop(&self) -> bool {
        matches!(self.state.as_str(), "running" | "unreachable")
    }

    pub fn can_delete(&self) -> bool {
        // Frozen bases may have dependent branches; let the engine enforce
        // dependencies too. Never silently force-stop an active machine.
        matches!(self.state.as_str(), "created" | "stopped" | "failed")
    }

    pub fn image_label(&self) -> &str {
        self.image.as_deref().unwrap_or("Bare Linux machine")
    }
}

pub fn parse_machines(bytes: &[u8]) -> Result<Vec<Machine>, String> {
    let mut machines: Vec<Machine> = serde_json::from_slice(bytes)
        .map_err(|e| format!("Cannot read the runtime's machine list: {e}"))?;
    machines.sort_by(|a, b| a.name.cmp(&b.name));
    if machines.iter().any(|m| m.name.is_empty())
        || machines.windows(2).any(|w| w[0].name == w[1].name)
    {
        return Err("The runtime returned an empty or duplicate machine name.".into());
    }
    machines.retain(|machine| !machine.engine_managed());
    Ok(machines)
}

#[derive(Clone, Debug)]
pub struct SharedFolder {
    pub host: String,
    pub guest: String,
    pub read_only: bool,
}
#[derive(Clone, Debug)]
pub struct PublishedPort {
    pub host: u16,
    pub guest: u16,
}
#[derive(Clone, Debug)]
pub struct NewMachine {
    pub name: String,
    pub image: String,
    pub cpus: u16,
    pub memory_mib: u32,
    pub network: bool,
    pub folders: Vec<SharedFolder>,
    pub ports: Vec<PublishedPort>,
}

impl Default for NewMachine {
    fn default() -> Self {
        Self {
            name: String::new(),
            image: String::new(),
            cpus: 2,
            memory_mib: 2048,
            network: false,
            folders: vec![],
            ports: vec![],
        }
    }
}

impl NewMachine {
    pub fn validate(&self) -> Result<(), String> {
        let name = self.name.as_bytes();
        if name.is_empty()
            || name.len() > 128
            || !name[0].is_ascii_alphanumeric()
            || !name
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
            || self.name.ends_with('-')
            || self.name.contains("--")
        {
            return Err("Use 1–128 letters, numbers, underscores or single dashes; start with a letter or number and do not end with a dash.".into());
        }
        if !(1..=64).contains(&self.cpus) || !(256..=262_144).contains(&self.memory_mib) {
            return Err("Choose 1–64 CPUs and 256–262144 MiB of memory.".into());
        }
        if self.image.contains(['\n', '\r', '\0']) || self.image.trim() == "-" {
            return Err(
                "Enter an image reference or local path; stdin is unavailable in Studio.".into(),
            );
        }
        for folder in &self.folders {
            if !std::path::Path::new(&folder.host).is_absolute()
                || !folder.guest.starts_with('/')
                || folder.host.contains(['\n', '\r', '\0'])
                || folder.guest.contains([':', '\n', '\r', '\0'])
            {
                return Err(
                    "Shared folders need an absolute host path and an absolute Linux guest path."
                        .into(),
                );
            }
        }
        if self.ports.iter().any(|p| p.host == 0 || p.guest == 0) {
            return Err("Published ports must be between 1 and 65535.".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum Operation {
    Refresh,
    ReadSettings(String),
    ListFiles {
        name: String,
        path: String,
    },
    TransferFile {
        name: String,
        guest: String,
        local: std::path::PathBuf,
        upload: bool,
    },
    UpdateSettings {
        original: Box<crate::machine_settings::Settings>,
        updated: Box<crate::machine_settings::Settings>,
    },
    Logs(String),
    Start(String),
    Stop(String),
    Delete(String),
    Create(NewMachine),
    Resume(String),
    Pause(String),
    Stats(String),
    Exec {
        name: String,
        command: String,
    },
}

impl Operation {
    pub fn is_mutation(&self) -> bool {
        !matches!(
            self,
            Self::Refresh
                | Self::ReadSettings(_)
                | Self::ListFiles { .. }
                | Self::Logs(_)
                | Self::Stats(_)
        )
    }

    pub fn label(&self) -> String {
        match self {
            Self::Refresh => "Refreshing machines".into(),
            Self::ListFiles { name, .. } => format!("Reading files in {name}"),
            Self::TransferFile { upload, .. } => if *upload {
                "Uploading file"
            } else {
                "Downloading file"
            }
            .into(),
            Self::ReadSettings(name) => format!("Reading settings for {name}"),
            Self::UpdateSettings { original, .. } => format!("Updating {}", original.name),
            Self::Logs(n) => format!("Reading logs for {n}"),
            Self::Start(n) => format!("Starting {n}"),
            Self::Stop(n) => format!("Stopping {n}"),
            Self::Delete(n) => format!("Deleting {n}"),
            Self::Resume(n) => format!("Resuming {n}"),
            Self::Pause(n) => format!("Pausing {n}"),
            Self::Stats(n) => format!("Measuring {n}"),
            Self::Exec { name, .. } => format!("Running command in {name}"),
            Self::Create(m) => format!("Creating {}", m.name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cli_schema_without_confusing_limits_with_usage() {
        let rows = parse_machines(br#"[{"name":"dev","state":"running","cpus":2,"memory_mib":4096,"image":null,"ports":1,"mounts":2,"future_field":true}]"#).unwrap();
        assert_eq!(rows[0].memory_mib, 4096);
        assert_eq!(rows[0].image_label(), "Bare Linux machine");
        assert!(rows[0].can_stop());
        assert!(!rows[0].can_delete());
        assert_eq!(rows[0].network, None);
        assert_eq!(rows[0].storage_gb, None);
        assert_eq!(rows[0].shared_folders, None);
        let detailed = parse_machines(br#"[{"name":"dev","state":"stopped","cpus":2,"memory_mib":4096,"network":false,"storage_gb":3,"overlay_gb":4,"shared_folders":[{"host":"/project files","guest":"/src","mode":"future-mode"}],"port_mappings":[{"host":8080,"guest":80,"protocol":"tcp"},{"host":8080,"guest":53,"protocol":"udp"}]}]"#).unwrap().remove(0);
        assert_eq!(detailed.storage_gb, Some(3));
        assert_eq!(detailed.overlay_gb, Some(4));
        assert_eq!(detailed.network, Some(false));
        assert_eq!(detailed.shared_folders.unwrap()[0].mode, "future-mode");
        let ports = detailed.port_mappings.unwrap();
        assert_eq!((ports[0].host, ports[0].guest), (8080, 80));
        assert_eq!(ports[1].protocol, "udp");
    }

    #[test]
    fn rejects_invalid_inventory_and_preserves_unknown_states() {
        assert!(parse_machines(b"not json").is_err());
        assert!(parse_machines(br#"[{"name":"x"}]"#).is_err());
        let mut machine =
            parse_machines(br#"[{"name":"x","state":"paused","cpus":2,"memory_mib":1024}]"#)
                .unwrap()
                .remove(0);
        for state in ["paused", "pausing", "frozen", "new-future-state"] {
            machine.state = state.into();
            assert!(!machine.can_start() && !machine.can_stop() && !machine.can_delete());
        }
        let duplicates = serde_json::json!([
            {"name":"x","state":"stopped","cpus":2,"memory_mib":1024},
            {"name":"x","state":"stopped","cpus":2,"memory_mib":1024}
        ]);
        assert!(parse_machines(&serde_json::to_vec(&duplicates).unwrap()).is_err());
    }

    #[test]
    fn inventory_separates_engine_ownership_without_guessing_from_names() {
        use serde_json::json;
        let row = |name: &str, labels: serde_json::Value| {
            json!({
                "name": name, "state": "running", "cpus": 2, "memory_mib": 1024, "labels": labels
            })
        };
        let rows = json!([
            row("docker-my-project", json!({})),
            row("buildkit-my-project", json!({"team": "build"})),
            row(
                "renamed-container-vm",
                json!({"smolvm.engine/container": "a".repeat(64)})
            ),
            row(
                "builder",
                json!({"smolvm.engine.builder": "/engine/buildkit"})
            ),
            row(
                "warm-base",
                json!({"smolvm.engine/base": "alpine cpus=2 mem=1024 rosetta=false", "smolvm.engine/base-engine": "/engine"})
            ),
            row("legacy", json!(null)),
            row("unknown-owner", json!({"smolvm.engine/future": "x"})),
            row(
                "invalid-container",
                json!({"smolvm.engine/container": "not-an-id"})
            ),
            row("incomplete-base", json!({"smolvm.engine/base": "image"})),
            row("empty-builder", json!({"smolvm.engine.builder": ""}))
        ]);
        let machines = parse_machines(&serde_json::to_vec(&rows).unwrap()).unwrap();
        assert_eq!(
            machines.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
            [
                "buildkit-my-project",
                "docker-my-project",
                "empty-builder",
                "incomplete-base",
                "invalid-container",
                "legacy",
                "unknown-owner"
            ]
        );
        // Ownership filtering must not conceal a broken identity response.
        let duplicate = row("same", json!({"smolvm.engine/container": "b".repeat(64)}));
        assert!(
            parse_machines(
                &serde_json::to_vec(&json!([duplicate, row("same", json!({}))])).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn create_validation_catches_unusable_input() {
        for name in [
            "",
            "--force",
            "../escape",
            "two words",
            "a;touch pwned",
            "a.b",
            "a--b",
            "a-",
        ] {
            let m = NewMachine {
                name: name.into(),
                ..Default::default()
            };
            assert!(m.validate().is_err());
        }
        let mut m = NewMachine {
            name: "my-dev_1".into(),
            ..Default::default()
        };
        assert!(m.validate().is_ok());
        m.image = "-".into();
        assert!(m.validate().is_err());
    }
}
