//! Project inventory comes from structured Docker labels, never comma-split label strings.
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};

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
}
impl Project {
    pub fn running(&self) -> usize {
        self.containers
            .iter()
            .filter(|c| c.state == "running")
            .count()
    }
    pub fn state(&self) -> &str {
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
            Project { name, containers }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
