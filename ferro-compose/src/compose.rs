//! Compose project management and orchestration.
//!
//! Provides project loading, file discovery, and orchestration commands.

use crate::service_graph::ServiceGraph;
use crate::{ComposeError, ComposeFile, ComposeResult};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Supported compose orchestration commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposeCommand {
    /// Start services in dependency order.
    Up,

    /// Stop services in reverse order.
    Down,

    /// List service status.
    Ps,

    /// Show service logs.
    Logs,
}

/// A loaded compose project with parsed configuration.
///
/// Represents a compose.yaml file that has been loaded from disk,
/// parsed, validated, and is ready for orchestration.
#[derive(Debug, Clone)]
pub struct ComposeProject {
    /// Path to the compose file.
    pub path: PathBuf,

    /// Parsed compose configuration.
    pub compose: ComposeFile,
}

impl ComposeProject {
    /// Load a compose project from a file path.
    ///
    /// Loads the compose file, parses .env file from the same directory,
    /// and validates the configuration.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the compose.yaml file.
    ///
    /// # Errors
    ///
    /// Returns [`ComposeError::Parse`] if the file cannot be read or parsed.
    pub fn load(path: &Path) -> ComposeResult<Self> {
        let content =
            fs::read_to_string(path).map_err(|err| ComposeError::Parse(err.to_string()))?;
        let mut env = load_env_file(path.parent().unwrap_or_else(|| Path::new(".")))?;
        for (key, value) in std::env::vars() {
            env.insert(key, value);
        }
        let compose = ComposeFile::parse(&content, &env)?;
        Ok(Self {
            path: path.to_path_buf(),
            compose,
        })
    }

    /// Validates service dependencies and builds a dependency graph.
    ///
    /// # Errors
    ///
    /// Returns [`ComposeError::Validation`] if there are cyclic dependencies.
    pub fn validate_dependencies(&self) -> ComposeResult<ServiceGraph> {
        ServiceGraph::from_compose(&self.compose)
    }

    /// Returns sorted list of all service names in the project.
    pub fn services(&self) -> Vec<String> {
        let mut names: Vec<String> = self.compose.services.keys().cloned().collect();
        names.sort();
        names
    }
}

/// Find a compose file, either explicitly specified or by searching common locations.
///
/// Searches in order: explicit path, compose.yaml, compose.yml, docker-compose.yml, docker-compose.yaml.
///
/// # Arguments
///
/// * `explicit` - Optional explicit path to use instead of searching.
///
/// # Errors
///
/// Returns [`ComposeError::Parse`] if no compose file is found.
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

    for name in [
        "compose.yaml",
        "compose.yml",
        "docker-compose.yml",
        "docker-compose.yaml",
    ] {
        let candidate = PathBuf::from(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(ComposeError::Parse(
        "no compose file found (compose.yaml/compose.yml/docker-compose.yml)".to_string(),
    ))
}

/// Computes the startup order for services based on dependencies.
///
/// Returns services in topological order, respecting `depends_on` relationships.
/// Services with no dependencies start first, followed by dependent services.
///
/// # Errors
///
/// Returns [`ComposeError::Validation`] if there are cyclic dependencies.
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

/// Computes the shutdown order (reverse of startup order).
///
/// Services are stopped in reverse dependency order so dependents stop before
/// their dependencies. The order comes from the same `depends_on` graph
/// `compose_up` uses — reversing the alphabetically-sorted service list got
/// this wrong whenever alphabetical and dependency order diverge.
pub fn compose_down(project: &ComposeProject) -> ComposeResult<Vec<String>> {
    let mut ordered = compose_up(project)?;
    ordered.reverse();
    Ok(ordered)
}

/// Lists all services in the project (sorted alphabetically).
pub fn compose_ps(project: &ComposeProject) -> ComposeResult<Vec<String>> {
    Ok(project.services())
}

/// Lists services for log viewing (same as `compose_ps`).
pub fn compose_logs(project: &ComposeProject) -> ComposeResult<Vec<String>> {
    Ok(project.services())
}

/// Loads environment variables from a .env file in the given directory.
fn load_env_file(dir: &Path) -> ComposeResult<HashMap<String, String>> {
    let mut env = HashMap::new();
    let env_path = dir.join(".env");
    if !env_path.exists() {
        return Ok(env);
    }

    let content =
        fs::read_to_string(&env_path).map_err(|err| ComposeError::Parse(err.to_string()))?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (key, raw_value) = trimmed
            .split_once('=')
            .ok_or_else(|| ComposeError::Parse(format!("invalid .env entry: {trimmed}")))?;
        let mut value = raw_value.trim().to_string();
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            value = value[1..value.len() - 1].to_string();
        }
        env.insert(key.trim().to_string(), value);
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::{
        compose_down, compose_logs, compose_ps, compose_up, find_compose_file, ComposeCommand,
        ComposeProject,
    };
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
        // CQ-01: Use expect with context instead of bare unwrap()
        let found = find_compose_file(Some(
            path.to_str()
                .expect("compose file path should be valid UTF-8"),
        ))
        .expect("found");
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
    fn compose_down_stops_dependents_before_dependencies() {
        // Alphabetical order (app, zk) diverges from dependency order
        // (zk before app): app depends_on zk, so down must stop app first.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("docker-compose.yml");
        fs::write(
            &path,
            r#"
version: "3.8"
services:
  app:
    image: busybox:latest
    depends_on:
      - zk
  zk:
    image: zookeeper:3.8
"#,
        )
        .expect("write compose");
        let project = ComposeProject::load(&path).expect("load");
        let down = compose_down(&project).expect("down");
        assert_eq!(
            down,
            vec!["app".to_string(), "zk".to_string()],
            "dependent 'app' must stop before its dependency 'zk'"
        );
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

    #[test]
    fn compose_loads_dotenv() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("compose.yaml");
        fs::write(dir.path().join(".env"), "IMAGE=nginx:latest\n").expect("write env");
        let content = r#"
version: "3.8"
services:
  web:
    image: ${IMAGE}
"#;
        fs::write(&path, content).expect("write compose");
        let project = ComposeProject::load(&path).expect("load");
        let image = project
            .compose
            .services
            .get("web")
            .and_then(|svc| svc.image.clone());
        assert_eq!(image.as_deref(), Some("nginx:latest"));
    }
}
