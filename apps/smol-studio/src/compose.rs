//! Project inventory comes from structured Docker labels, never comma-split label strings.
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    io::Write,
    path::{Path, PathBuf},
};

/// Only file locations and the resolved identity are saved, never expanded config or secrets.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Source {
    pub files: Vec<PathBuf>,
    pub name: Option<String>,
}
impl Source {
    pub fn single(file: PathBuf) -> Self {
        Self {
            files: vec![file],
            name: None,
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.files.is_empty() || self.files.len() > 32 {
            return Err("Choose between one and 32 Compose files.".into());
        }
        if self
            .files
            .iter()
            .any(|p| !p.is_absolute() || p.to_str().is_none())
        {
            return Err("Compose files must have absolute, UTF-8 paths.".into());
        }
        if let Some(name) = &self.name {
            validate_name(name)?;
        }
        Ok(())
    }
    pub fn args(&self) -> Result<Vec<String>, String> {
        self.validate()?;
        let mut args = vec!["--context".into(), "smol".into(), "compose".into()];
        if let Some(name) = &self.name {
            args.extend(["--project-name".into(), name.clone()]);
        }
        for file in &self.files {
            if !file.is_file() {
                return Err(format!(
                    "Compose file is missing or unreadable: {}",
                    file.display()
                ));
            }
            args.extend(["--file".into(), file.to_str().unwrap().to_owned()]);
        }
        Ok(args)
    }
}

pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
        || !name.as_bytes()[0].is_ascii_alphanumeric()
    {
        return Err("Invalid Compose project name.".into());
    }
    Ok(())
}

pub fn resolved_name(bytes: &[u8]) -> Result<String, String> {
    #[derive(Deserialize)]
    struct Identity {
        name: String,
    }
    let identity: Identity = serde_json::from_slice(bytes)
        .map_err(|_| "Compose did not return a valid project identity.")?;
    validate_name(&identity.name)?;
    Ok(identity.name)
}

pub(crate) fn source_store(runtime: &crate::runtime::Runtime) -> Result<PathBuf, String> {
    Ok(match &runtime.state_dir {
        Some(path) => path.join("studio-compose-projects.json"),
        None => crate::preferences::directory()?.join("compose-projects.json"),
    })
}

pub(crate) fn load_sources(path: &Path) -> Result<BTreeMap<String, Source>, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(format!("Cannot read saved Compose projects: {e}")),
    };
    let sources: BTreeMap<String, Source> = serde_json::from_slice(&bytes)
        .map_err(|_| "Saved Compose projects could not be read; the file was left unchanged.")?;
    for (name, source) in &sources {
        source.validate()?;
        if source.name.as_ref() != Some(name) {
            return Err("Saved Compose project identity does not match its source.".into());
        }
    }
    Ok(sources)
}

pub(crate) fn save_source(path: &Path, name: &str, source: Option<Source>) -> Result<(), String> {
    validate_name(name)?;
    let mut sources = load_sources(path)?;
    if let Some(source) = source {
        source.validate()?;
        if source.name.as_deref() != Some(name) {
            return Err("Project identity does not match its source.".into());
        }
        sources.insert(name.into(), source);
    } else {
        sources.remove(name);
    }
    let parent = path
        .parent()
        .ok_or("Cannot locate saved project directory.")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec_pretty(&sources).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}

pub(crate) fn attach_sources(projects: &mut Vec<Project>, sources: BTreeMap<String, Source>) {
    for (name, source) in sources {
        if let Some(project) = projects.iter_mut().find(|p| p.name == name) {
            project.source = Some(source);
        } else {
            projects.push(Project {
                name,
                containers: Vec::new(),
                source: Some(source),
            });
        }
    }
    projects.sort_by(|a, b| a.name.cmp(&b.name));
}

pub const LIST_FORMAT: &str = r#"{"id":{{json .ID}},"name":{{json .Names}},"image":{{json .Image}},"state":{{json .State}},"project":{{json (.Label "com.docker.compose.project")}},"service":{{json (.Label "com.docker.compose.service")}},"one_off":{{json (.Label "com.docker.compose.oneoff")}}}"#;

#[derive(Clone, Debug, Deserialize)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub project: String,
    pub service: String,
    one_off: String,
}
impl Container {
    pub fn is_job(&self) -> bool {
        self.one_off.eq_ignore_ascii_case("true")
    }
    pub fn can_start(&self) -> bool {
        !self.is_job() && matches!(self.state.as_str(), "created" | "exited")
    }
    pub fn can_stop(&self) -> bool {
        matches!(self.state.as_str(), "running" | "restarting")
    }
}

#[derive(Clone, Debug)]
pub struct Project {
    pub name: String,
    pub containers: Vec<Container>,
    pub source: Option<Source>,
}
impl Project {
    pub fn running(&self) -> usize {
        self.containers
            .iter()
            .filter(|c| c.state == "running")
            .count()
    }
    pub fn state(&self) -> &str {
        if self.containers.is_empty() {
            return "not created";
        }
        // Completed `compose run` jobs do not make healthy services look partial.
        let has_services = self.containers.iter().any(|c| !c.is_job());
        let services: Vec<_> = self
            .containers
            .iter()
            .filter(|c| !has_services || !c.is_job())
            .collect();
        let running = services.iter().filter(|c| c.state == "running").count();
        if !services.is_empty() && running == services.len() {
            "running"
        } else if running > 0 {
            "partial"
        } else if self.containers.iter().any(|c| c.state == "restarting") {
            "restarting"
        } else if self.containers.iter().any(|c| c.state == "paused") {
            "paused"
        } else {
            "stopped"
        }
    }
    pub fn services(&self) -> BTreeMap<&str, Vec<&Container>> {
        let mut services = BTreeMap::<&str, Vec<&Container>>::new();
        for container in &self.containers {
            services
                .entry(&container.service)
                .or_default()
                .push(container);
        }
        services
    }
}

pub fn parse(bytes: &[u8]) -> Result<Vec<Project>, String> {
    let mut projects = BTreeMap::<String, Vec<Container>>::new();
    let mut ids = HashSet::new();
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let container: Container = serde_json::from_slice(line)
            .map_err(|_| "Docker returned an invalid Compose inventory.")?;
        crate::docker::validate_container_id(&container.id)?;
        if !ids.insert(container.id.clone()) {
            return Err("Docker returned duplicate Compose container IDs.".into());
        }
        if container.project.is_empty() || container.service.is_empty() {
            continue;
        }
        projects
            .entry(container.project.clone())
            .or_default()
            .push(container);
    }
    Ok(projects
        .into_iter()
        .map(|(name, mut containers)| {
            containers.sort_by(|a, b| {
                (&a.service, a.is_job(), &a.name, &a.id).cmp(&(
                    &b.service,
                    b.is_job(),
                    &b.name,
                    &b.id,
                ))
            });
            Project {
                name,
                containers,
                source: None,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sources_preserve_order_identity_and_missing_file_bookmarks() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("base, with spaces.yaml");
        let second = dir.path().join("override.yaml ");
        std::fs::write(&first, "services: {}").unwrap();
        std::fs::write(&second, "services: {}").unwrap();
        let source = Source {
            files: vec![first.clone(), second.clone()],
            name: Some("shop-dev".into()),
        };
        assert_eq!(
            source.args().unwrap(),
            [
                "--context",
                "smol",
                "compose",
                "--project-name",
                "shop-dev",
                "--file",
                first.to_str().unwrap(),
                "--file",
                second.to_str().unwrap()
            ]
        );
        let store = dir.path().join("studio/projects.json");
        save_source(&store, "shop-dev", Some(source.clone())).unwrap();
        std::fs::remove_file(&second).unwrap();
        let sources = load_sources(&store).unwrap();
        assert_eq!(sources["shop-dev"], source);
        assert!(sources["shop-dev"].args().unwrap_err().contains("missing"));
        let mut projects = Vec::new();
        attach_sources(&mut projects, sources);
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].state(), "not created");
        save_source(&store, "shop-dev", None).unwrap();
        assert!(load_sources(&store).unwrap().is_empty());
        assert!(first.exists());
    }

    #[test]
    fn invalid_source_identity_and_corrupt_store_are_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("projects.json");
        std::fs::write(&store, "broken existing settings").unwrap();
        let source = Source {
            files: vec![dir.path().join("compose.yaml")],
            name: Some("shop".into()),
        };
        assert!(save_source(&store, "shop", Some(source)).is_err());
        assert_eq!(
            std::fs::read_to_string(&store).unwrap(),
            "broken existing settings"
        );
        for name in ["", "-bad", "_bad", "Bad", "bad name", "../bad"] {
            assert!(validate_name(name).is_err());
        }
        assert_eq!(resolved_name(br#"{"name":"shop","services":{"web":{"environment":{"PASSWORD":"never retained"}}}}"#).unwrap(), "shop");
        assert!(resolved_name(br#"{"services":{}}"#).is_err());
    }

    #[test]
    fn groups_projects_replicas_and_jobs_without_losing_label_contents() {
        let row = |id: &str, project: &str, service: &str, state: &str, job: &str| {
            json!({
            "id":id,"project":project,"service":service,"state":state,"one_off":job,
            "name":format!("{project}-{service}-{id}"),"image":"registry.example/team/web:latest"
        }).to_string()
        };
        let input = [
            row("aa", "shop", "web", "running", "False"),
            row("bb", "shop", "web", "exited", "False"),
            row("cc", "shop", "migrate", "exited", "True"),
            row("dd", "shop-old", "web", "running", "false"),
            row(
                "ee",
                "project,with=punctuation",
                "service\"name",
                "created",
                "",
            ),
        ]
        .join("\n");
        let projects = parse(input.as_bytes()).unwrap();
        assert_eq!(projects.len(), 3);
        let project = projects.iter().find(|p| p.name == "shop").unwrap();
        assert_eq!(project.services()["web"].len(), 2);
        assert_eq!(project.running(), 1);
        assert_eq!(project.state(), "partial");
        assert_eq!(
            project
                .containers
                .iter()
                .filter(|c| c.can_start())
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>(),
            ["bb"]
        );
        assert_eq!(projects[0].name, "project,with=punctuation");
        let healthy = parse(
            [
                row("aa", "shop", "web", "running", "False"),
                row("cc", "shop", "migrate", "exited", "True"),
            ]
            .join("\n")
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(healthy[0].state(), "running");
        let job_only = parse(row("aa", "job", "task", "running", "True").as_bytes()).unwrap();
        assert_eq!(job_only[0].state(), "running");
        assert!(
            parse(format!("{input}\n{}", row("aa", "other", "web", "running", "false")).as_bytes())
                .is_err()
        );
        assert!(parse(row("--force", "shop", "web", "running", "false").as_bytes()).is_err());
        assert!(parse(b"{\"project\":\"shop\"}").is_err());
    }
}
