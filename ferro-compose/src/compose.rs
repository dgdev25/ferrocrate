use crate::{ComposeError, ComposeFile, ComposeResult};
use crate::service_graph::ServiceGraph;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposeCommand {
    Up,
    Down,
    Ps,
    Logs,
}

#[derive(Debug, Clone)]
pub struct ComposeProject {
    pub path: PathBuf,
    pub compose: ComposeFile,
}

impl ComposeProject {
    pub fn load(path: &Path) -> ComposeResult<Self> {
        let content = fs::read_to_string(path)
            .map_err(|err| ComposeError::Parse(err.to_string()))?;
        let env = HashMap::new();
        let compose = ComposeFile::parse(&content, &env)?;
        Ok(Self {
            path: path.to_path_buf(),
            compose,
        })
    }

    pub fn validate_dependencies(&self) -> ComposeResult<ServiceGraph> {
        ServiceGraph::from_compose(&self.compose)
    }

    pub fn services(&self) -> Vec<String> {
        let mut names: Vec<String> = self.compose.services.keys().cloned().collect();
        names.sort();
        names
    }
}

pub fn find_compose_file(explicit: Option<&str>) -> ComposeResult<PathBuf> {
    if let Some(path) = explicit {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return Ok(candidate);
        }
        return Err(ComposeError::Parse(format!(
            "compose file not found: {path}"
        )));
    }

    for name in ["compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"] {
        let candidate = PathBuf::from(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(ComposeError::Parse(
        "no compose file found (compose.yaml/compose.yml/docker-compose.yml)".to_string(),
    ))
}

pub fn compose_up(project: &ComposeProject) -> ComposeResult<Vec<String>> {
    let graph = project.validate_dependencies()?;
    let batches = graph.start_batches();
    let mut ordered = Vec::new();
    for batch in batches {
        for service in batch {
            ordered.push(service);
        }
    }
    Ok(ordered)
}

pub fn compose_down(project: &ComposeProject) -> ComposeResult<Vec<String>> {
    let mut services = project.services();
    services.reverse();
    Ok(services)
}

pub fn compose_ps(project: &ComposeProject) -> ComposeResult<Vec<String>> {
    Ok(project.services())
}

pub fn compose_logs(project: &ComposeProject) -> ComposeResult<Vec<String>> {
    Ok(project.services())
}

#[cfg(test)]
mod tests {
    use super::{ComposeCommand, ComposeProject, compose_down, compose_logs, compose_ps, compose_up, find_compose_file};
    use std::fs;
    use std::path::PathBuf;

    fn write_compose(path: &PathBuf) {
        let content = r#"
version: "3.8"
services:
  web:
    image: nginx:latest
    depends_on:
      - db
  db:
    image: postgres:14
"#;
        fs::write(path, content).expect("write compose");
    }

    #[test]
    fn finds_explicit_compose_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("compose.yaml");
        write_compose(&path);
        let found = find_compose_file(Some(path.to_str().unwrap())).expect("found");
        assert_eq!(found, path);
    }

    #[test]
    fn handles_missing_compose_file() {
        let err = find_compose_file(Some("missing.yml")).expect_err("expected error");
        let message = format!("{err}");
        assert!(message.contains("not found"));
    }

    #[test]
    fn compose_up_orders_services() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("docker-compose.yml");
        write_compose(&path);
        let project = ComposeProject::load(&path).expect("load");
        let ordered = compose_up(&project).expect("up");
        assert_eq!(ordered.first().map(|v| v.as_str()), Some("db"));
    }

    #[test]
    fn compose_down_reverses_services() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("docker-compose.yml");
        write_compose(&path);
        let project = ComposeProject::load(&path).expect("load");
        let down = compose_down(&project).expect("down");
        assert_eq!(down.last().map(|v| v.as_str()), Some("db"));
    }

    #[test]
    fn compose_ps_lists_services() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("docker-compose.yml");
        write_compose(&path);
        let project = ComposeProject::load(&path).expect("load");
        let services = compose_ps(&project).expect("ps");
        assert_eq!(services.len(), 2);
    }

    #[test]
    fn compose_logs_lists_services() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("docker-compose.yml");
        write_compose(&path);
        let project = ComposeProject::load(&path).expect("load");
        let services = compose_logs(&project).expect("logs");
        assert_eq!(services.len(), 2);
    }

    #[test]
    fn compose_command_enum() {
        assert_eq!(ComposeCommand::Up, ComposeCommand::Up);
    }
}
