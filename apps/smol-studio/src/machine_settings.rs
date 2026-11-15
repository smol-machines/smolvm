use serde::Deserialize;
use std::{collections::HashSet, ffi::OsString, path::Path};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Folder {
    pub host: String,
    pub guest: String,
    pub mode: FolderMode,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum FolderMode {
    #[serde(rename = "ro")]
    ReadOnly,
    #[serde(rename = "rw")]
    ReadWrite,
    #[serde(rename = "staged")]
    Staged,
}

impl FolderMode {
    pub fn argument(self) -> &'static str {
        match self {
            Self::ReadOnly => "ro",
            Self::ReadWrite => "rw",
            Self::Staged => "staged",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::ReadOnly => "Read only",
            Self::ReadWrite => "Read and write",
            Self::Staged => "Staged copy",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Port {
    pub host: u16,
    pub guest: u16,
    pub protocol: Protocol,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Port {
    fn argument(&self) -> String {
        format!(
            "{}:{}/{}",
            self.host,
            self.guest,
            if self.protocol == Protocol::Tcp {
                "tcp"
            } else {
                "udp"
            }
        )
    }
}

/// Only editable, non-secret configuration is retained from CLI status output.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Settings {
    pub name: String,
    pub state: String,
    pub created_at: u64,
    pub cpus: u16,
    pub memory_mib: u32,
    pub network: bool,
    pub storage_gb: Option<u64>,
    pub overlay_gb: Option<u64>,
    pub shared_folders: Vec<Folder>,
    pub port_mappings: Vec<Port>,
}

impl Settings {
    pub fn parse(bytes: &[u8], expected: &str) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(flatten)]
            settings: Settings,
            mounts: usize,
            ports: usize,
        }
        let response: Response = serde_json::from_slice(bytes).map_err(|e| format!("Cannot read machine settings: {e}. Use a Smol CLI build with detailed shared-folder and port information."))?;
        let settings = response.settings;
        if response.mounts != settings.shared_folders.len()
            || response.ports != settings.port_mappings.len()
        {
            return Err("The runtime returned incomplete folder or port details; settings were not changed.".into());
        }
        if settings.name != expected {
            return Err("The runtime returned settings for a different machine.".into());
        }
        Ok(settings)
    }

    pub fn editable(&self) -> bool {
        matches!(self.state.as_str(), "created" | "stopped")
    }

    pub fn update_args(&self, next: &Self) -> Result<Vec<OsString>, String> {
        if !self.editable() {
            return Err("Stop the machine before editing its settings.".into());
        }
        if self.name != next.name || self.created_at != next.created_at || self.state != next.state
        {
            return Err("Machine identity or state changed. Reload its settings.".into());
        }
        if next.cpus != self.cpus && !(1..=16).contains(&next.cpus) {
            return Err("Choose 1–16 CPUs, the runtime's supported range.".into());
        }
        if next.memory_mib < 64 {
            return Err("Memory must be at least 64 MiB.".into());
        }
        let mut targets = HashSet::new();
        for folder in &next.shared_folders {
            if !Path::new(&folder.host).is_absolute()
                || folder.host.contains(['\n', '\r', '\0'])
                || !folder.guest.starts_with('/')
                || folder.guest.contains([':', '\n', '\r', '\0'])
                || folder.guest.split('/').any(|s| matches!(s, "." | ".."))
                || folder.guest.contains("//")
            {
                return Err(
                    "Shared folders need absolute host and guest paths without relative segments."
                        .into(),
                );
            }
            if !targets.insert(folder.guest.trim_end_matches('/')) {
                return Err("Each shared folder needs a different guest path.".into());
            }
        }
        let mut hosts = HashSet::new();
        for port in &next.port_mappings {
            if port.host == 0 || port.guest == 0 || !hosts.insert((port.host, port.protocol)) {
                return Err("Use ports from 1–65535, with a different host port for each mapping of the same protocol.".into());
            }
        }
        if !next.network && !next.port_mappings.is_empty() {
            return Err("Enable networking to use published ports.".into());
        }
        let mut args = Vec::new();
        let mut add = |flag: &str, value: String| {
            args.extend([flag.into(), value.into()]);
        };
        if next.cpus != self.cpus {
            add("--cpus", next.cpus.to_string());
        }
        if next.memory_mib != self.memory_mib {
            add("--mem", next.memory_mib.to_string());
        }
        for (flag, old, new) in [
            ("--storage", self.storage_gb, next.storage_gb),
            ("--overlay", self.overlay_gb, next.overlay_gb),
        ] {
            if new != old {
                let value = new.ok_or("Disk sizes cannot be reset to the runtime default.")?;
                if value == 0 || old.is_some_and(|old| value < old) {
                    return Err("Disks can only grow; their existing data is retained.".into());
                }
                add(flag, value.to_string());
            }
        }
        // Replace the folder sequence in one CLI update to preserve mount order
        // and staged/live modes, including edits to a folder's access mode.
        if next.shared_folders != self.shared_folders {
            for folder in &self.shared_folders {
                add(
                    "--remove-volume",
                    format!("{}:{}", folder.host, folder.guest),
                );
            }
            for folder in &next.shared_folders {
                add(
                    "--volume",
                    format!(
                        "{}:{}:{}",
                        folder.host,
                        folder.guest,
                        folder.mode.argument()
                    ),
                );
            }
        }
        for port in &self.port_mappings {
            if !next.port_mappings.contains(port) {
                add("--remove-port", port.argument());
            }
        }
        for port in &next.port_mappings {
            if !self.port_mappings.contains(port) {
                add("--port", port.argument());
            }
        }
        if next.network != self.network {
            args.push(if next.network { "--net" } else { "--no-net" }.into());
        }
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings() -> Settings {
        Settings::parse(br#"{"name":"dev","state":"stopped","created_at":1,"cpus":2,"memory_mib":512,"network":true,"storage_gb":2,"overlay_gb":1,"mounts":0,"ports":0,"shared_folders":[],"port_mappings":[]}"#, "dev").unwrap()
    }
    #[test]
    fn settings_require_details_and_matching_identity() {
        assert!(Settings::parse(br#"{"name":"dev","cpus":2,"mounts":1}"#, "dev").is_err());
        let base = settings();
        let mut next = base.clone();
        next.name = "other".into();
        assert!(base.update_args(&next).is_err());
        next = base.clone();
        next.created_at += 1;
        assert!(base.update_args(&next).is_err());
    }
    #[test]
    fn updates_preserve_unedited_fields_and_literal_arguments() {
        let base = settings();
        let mut next = base.clone();
        next.memory_mib = 1024;
        let host = std::env::temp_dir()
            .join("folder ; $(touch nope)")
            .to_string_lossy()
            .into_owned();
        next.shared_folders.push(Folder {
            host: host.clone(),
            guest: "/data".into(),
            mode: FolderMode::Staged,
        });
        next.port_mappings.push(Port {
            host: 8080,
            guest: 53,
            protocol: Protocol::Udp,
        });
        let args = base.update_args(&next).unwrap();
        assert!(args.windows(2).any(|w| w
            == [
                OsString::from("--volume"),
                OsString::from(format!("{host}:/data:staged"))
            ]));
        assert!(args.contains(&"8080:53/udp".into()));
        assert!(
            !args.contains(&"--cpus".into())
                && !args.contains(&"--net".into())
                && !args.contains(&"--storage".into())
        );
        assert!(base.update_args(&base).unwrap().is_empty());
    }
    #[test]
    fn unsafe_or_conflicting_edits_are_rejected() {
        let base = settings();
        let mut next = base.clone();
        next.storage_gb = Some(1);
        assert!(base.update_args(&next).is_err());
        next = base.clone();
        next.port_mappings = vec![
            Port {
                host: 8080,
                guest: 80,
                protocol: Protocol::Tcp
            };
            2
        ];
        assert!(base.update_args(&next).is_err());
        next.port_mappings[1].protocol = Protocol::Udp;
        assert!(base.update_args(&next).is_ok());
        next.network = false;
        assert!(base.update_args(&next).is_err());
        let mut running = base.clone();
        running.state = "running".into();
        assert!(running.update_args(&running).is_err());
    }
}
