//! Project inventory comes from structured Docker labels, never comma-split label strings.
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    io::Write,
    path::{Path, PathBuf},
};

/// Only file locations and the resolved identity are saved, never expanded config or secrets.
#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct Source {
    pub files: Vec<PathBuf>,
    pub name: Option<String>,
    #[serde(default)]
    pub env_files: Vec<PathBuf>,
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub project_dir: Option<PathBuf>,
}
impl Source {
    pub fn single(file: PathBuf) -> Self {
        Self {
            files: vec![file],
            name: None,
            ..Self::default()
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
        if self.env_files.len() > 32
            || self
                .env_files
                .iter()
                .any(|p| !p.is_absolute() || p.to_str().is_none())
        {
            return Err("Choose up to 32 environment files with absolute, UTF-8 paths.".into());
        }
        if self.profiles.len() > 32
            || self.profiles.iter().any(|p| {
                p != "*"
                    && (p.is_empty()
                        || !p.as_bytes()[0].is_ascii_alphanumeric()
                        || !p
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c)))
            })
        {
            return Err("Use up to 32 profile names containing letters, numbers, dots, underscores or hyphens; use * for all profiles.".into());
        }
        if self
            .project_dir
            .as_ref()
            .is_some_and(|p| !p.is_absolute() || p.to_str().is_none())
        {
            return Err("Project directory must be an absolute, UTF-8 path.".into());
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
        if let Some(directory) = &self.project_dir {
            if !directory.is_dir() {
                return Err(format!(
                    "Project directory is unavailable: {}",
                    directory.display()
                ));
            }
            args.extend([
                "--project-directory".into(),
                directory.to_str().unwrap().to_owned(),
            ]);
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
        for file in &self.env_files {
            if !file.is_file() {
                return Err(format!(
                    "Environment file is missing or unreadable: {}",
                    file.display()
                ));
            }
            args.extend(["--env-file".into(), file.to_str().unwrap().to_owned()]);
        }
        for profile in &self.profiles {
            args.extend(["--profile".into(), profile.clone()]);
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

pub const LIST_FORMAT: &str = r#"{"id":{{json .ID}},"name":{{json .Names}},"image":{{json .Image}},"state":{{json .State}},"project":{{json (.Label "com.docker.compose.project")}},"service":{{json (.Label "com.docker.compose.service")}},"one_off":{{json (.Label "com.docker.compose.oneoff")}},"config_files":{{json (.Label "com.docker.compose.project.config_files")}},"working_dir":{{json (.Label "com.docker.compose.project.working_dir")}},"environment_file":{{json (.Label "com.docker.compose.project.environment_file")}}}"#;

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct RecordedSource {
    #[serde(default)]
    pub config_files: String,
    #[serde(default)]
    pub working_dir: String,
    #[serde(default)]
    pub environment_file: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub project: String,
    pub service: String,
    one_off: String,
    #[serde(flatten)]
    pub recorded: RecordedSource,
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
    pub fn recorded_source(&self) -> Result<&RecordedSource, String> {
        let has_services = self.containers.iter().any(|c| !c.is_job());
        let mut records = self
            .containers
            .iter()
            .filter(|c| !has_services || !c.is_job())
            .map(|c| &c.recorded);
        let first = records
            .next()
            .ok_or("This project no longer has containers.")?;
        if first.config_files.is_empty() {
            return Err("Compose did not record file locations for this project. Choose the files manually.".into());
        }
        if records.any(|r| r != first) {
            return Err("The service containers record different project settings. Choose the files manually.".into());
        }
        Ok(first)
    }
    pub fn discover_source(&self) -> Result<Source, String> {
        let record = self.recorded_source()?;
        let source = Source {
            files: recorded_paths(&record.config_files)?,
            env_files: if record.environment_file.is_empty() {
                Vec::new()
            } else {
                recorded_paths(&record.environment_file)?
            },
            name: Some(self.name.clone()),
            project_dir: Some(PathBuf::from(&record.working_dir)),
            profiles: Vec::new(),
        };
        source.args()?;
        Ok(source)
    }
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

// Compose joins absolute paths with commas without escaping filenames. Resolve
// only a unique partition into existing files, on the action worker, never UI.
fn recorded_paths(label: &str) -> Result<Vec<PathBuf>, String> {
    let parts: Vec<_> = label.split(',').collect();
    if label.len() > 16384 || parts.len() > 64 {
        return Err(
            "Recorded file locations exceed the import limit. Choose the files manually.".into(),
        );
    }
    let mut solutions: Vec<Vec<Vec<PathBuf>>> = vec![Vec::new(); parts.len() + 1];
    solutions[parts.len()].push(Vec::new());
    for start in (0..parts.len()).rev() {
        for end in start + 1..=parts.len() {
            if solutions[end].is_empty() {
                continue;
            }
            let path = PathBuf::from(parts[start..end].join(","));
            if !path.is_absolute() || !path.is_file() {
                continue;
            }
            for suffix in solutions[end].clone() {
                if suffix.len() >= 32 {
                    continue;
                }
                let mut candidate = vec![path.clone()];
                candidate.extend(suffix);
                solutions[start].push(candidate);
                if solutions[start].len() == 2 {
                    break;
                }
            }
            if solutions[start].len() == 2 {
                break;
            }
        }
    }
    match solutions[0].len() {
        1 => Ok(solutions[0].remove(0)),
        0 => Err("The recorded files are unavailable on this computer. Choose their current locations manually.".into()),
        _ => Err("Commas make the recorded file locations ambiguous. Choose the files manually.".into()),
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
            ..Source::default()
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
            ..Source::default()
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
    fn environment_order_profiles_and_legacy_bookmarks_are_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let compose = dir.path().join("compose.yaml");
        let first = dir.path().join("base env");
        let last = dir.path().join("override.env");
        for path in [&compose, &first, &last] {
            std::fs::write(path, "PRIVATE_VALUE=not stored").unwrap();
        }
        let source = Source {
            files: vec![compose.clone()],
            name: Some("shop".into()),
            env_files: vec![first.clone(), last.clone()],
            profiles: vec!["debug".into(), "metrics.dev".into()],
            project_dir: None,
        };
        let args = source.args().unwrap();
        assert_eq!(
            &args[7..],
            &[
                "--env-file",
                first.to_str().unwrap(),
                "--env-file",
                last.to_str().unwrap(),
                "--profile",
                "debug",
                "--profile",
                "metrics.dev"
            ]
        );
        let store = dir.path().join("saved.json");
        save_source(&store, "shop", Some(source.clone())).unwrap();
        assert_eq!(load_sources(&store).unwrap()["shop"], source);
        assert!(
            !std::fs::read_to_string(&store)
                .unwrap()
                .contains("PRIVATE_VALUE")
        );
        let legacy: Source =
            serde_json::from_value(json!({"files":[compose],"name":"shop"})).unwrap();
        assert!(legacy.env_files.is_empty() && legacy.profiles.is_empty());
        for profile in ["--bad", "a,b", "has space", "", "bad/dir"] {
            let mut invalid = source.clone();
            invalid.profiles = vec![profile.into()];
            assert!(invalid.validate().is_err());
        }
        let mut all = source.clone();
        all.profiles = vec!["*".into()];
        assert!(all.validate().is_ok());
        std::fs::remove_file(&last).unwrap();
        assert!(load_sources(&store).is_ok());
        assert!(
            source
                .args()
                .unwrap_err()
                .contains("Environment file is missing")
        );
    }

    #[test]
    fn discovery_preserves_commas_order_directory_and_requires_consistent_service_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base, with spaces.yaml");
        let overlay = dir.path().join("override.yaml");
        let env = dir.path().join("local, dev.env");
        for p in [&base, &overlay, &env] {
            std::fs::write(p, "fixture").unwrap();
        }
        let row = |id: &str, job: &str, files: &str| {
            json!({"id":id,"name":"service","image":"alpine","state":"running","project":"shop","service":"web","one_off":job,"config_files":files,"working_dir":dir.path(),"environment_file":env}).to_string()
        };
        let files = format!("{},{}", base.display(), overlay.display());
        let input = [
            row("aa", "False", &files),
            row("bb", "False", &files),
            row("cc", "True", "/other/job.yaml"),
        ]
        .join("\n");
        let project = parse(input.as_bytes()).unwrap().remove(0);
        let source = project.discover_source().unwrap();
        assert_eq!(source.files, vec![base, overlay.clone()]);
        assert_eq!(source.env_files, vec![env.clone()]);
        assert_eq!(source.project_dir.as_deref(), Some(dir.path()));
        assert_eq!(source.name.as_deref(), Some("shop"));
        assert!(source.profiles.is_empty());
        assert!(project.source.is_none());
        assert!(
            source
                .args()
                .unwrap()
                .windows(2)
                .any(|a| a == ["--project-directory", dir.path().to_str().unwrap()])
        );
        let conflict = [
            row("aa", "False", &files),
            row("bb", "False", "/other/project.yaml"),
        ]
        .join("\n");
        assert!(
            parse(conflict.as_bytes()).unwrap()[0]
                .discover_source()
                .unwrap_err()
                .contains("different")
        );
        std::fs::remove_file(overlay).unwrap();
        assert!(
            project
                .discover_source()
                .unwrap_err()
                .contains("unavailable")
        );
        assert!(recorded_paths("relative.yaml").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn ambiguous_recorded_paths_are_not_guessed() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        std::fs::write(&first, "").unwrap();
        std::fs::write(&second, "").unwrap();
        let label = format!("{},{}", first.display(), second.display());
        let combined = PathBuf::from(&label);
        std::fs::create_dir_all(combined.parent().unwrap()).unwrap();
        std::fs::write(&combined, "").unwrap();
        assert!(recorded_paths(&label).unwrap_err().contains("ambiguous"));
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
