//! FerroCrate Compose - Docker Compose file parser and orchestrator.
//!
//! This crate provides Docker Compose file parsing, validation, and orchestration:
//! - YAML parsing with variable interpolation
//! - Dependency graph analysis and cycle detection
//! - Service startup ordering and shutdown sequencing
//!
//! ## Example
//!
//! ```ignore
//! use ferro_compose::{ComposeFile, ComposeProject};
//! use std::path::Path;
//!
//! let project = ComposeProject::load(Path::new("compose.yaml"))?;
//! let services = compose_up(&project)?;
//! println!("Start order: {:?}", services);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Errors that can occur during compose file parsing or validation.
#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    /// Failed to parse compose YAML or resolve variables.
    #[error("compose parse error: {0}")]
    Parse(String),

    /// Compose file failed validation (invalid structure, cycles, etc).
    #[error("compose validation error: {0}")]
    Validation(String),
}

/// Result type for compose operations.
pub type ComposeResult<T> = Result<T, ComposeError>;

/// Parsed Docker Compose file with services, networks, and volumes.
///
/// This is the root structure representing a compose.yaml file.
/// Supports version 3.x format with variable interpolation.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ComposeFile {
    /// Compose file format version (e.g., "3.8").
    pub version: Option<String>,

    /// Service definitions indexed by name.
    pub services: HashMap<String, Service>,

    /// Named network definitions.
    pub networks: Option<HashMap<String, Network>>,

    /// Named volume definitions.
    pub volumes: Option<HashMap<String, Volume>>,
}

/// Docker Compose service definition.
///
/// Represents a single service within a compose file with its configuration
/// including image, build context, networking, and deployment options.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Service {
    /// Container image to use (e.g., "nginx:latest").
    pub image: Option<String>,

    /// Build configuration for local image builds.
    pub build: Option<Build>,

    /// Command to run in the container (overrides image CMD).
    pub command: Option<Command>,

    /// Entrypoint to use (overrides image ENTRYPOINT).
    pub entrypoint: Option<String>,

    /// Environment variables as key-value pairs or list.
    pub environment: Option<Environment>,

    /// Path to env file(s) to load.
    pub env_file: Option<Vec<String>>,

    /// Port mappings (e.g., "8080:80").
    pub ports: Option<Vec<String>>,

    /// Volume mount specifications.
    pub volumes: Option<Vec<String>>,

    /// Networks to attach the service to.
    pub networks: Option<Vec<String>>,

    /// Network mode (e.g., "host", "service:web").
    #[serde(rename = "network_mode")]
    pub network_mode: Option<String>,

    /// Service dependencies that must start first.
    pub depends_on: Option<DependsOn>,

    /// Restart policy ("no", "always", "on-failure", "unless-stopped").
    pub restart: Option<String>,

    /// Health check configuration.
    pub healthcheck: Option<HealthCheck>,

    /// Deployment and resource configuration.
    pub deploy: Option<Deploy>,

    /// Service labels for metadata.
    pub labels: Option<HashMap<String, String>>,

    /// Profile names that enable this service.
    pub profiles: Option<Vec<String>>,
}

/// Build configuration for creating container images.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Build {
    /// Build context path (relative to compose file).
    pub context: Option<String>,

    /// Path to Dockerfile (default: "Dockerfile").
    pub dockerfile: Option<String>,

    /// Build arguments as key-value pairs.
    pub args: Option<HashMap<String, String>>,
}

/// Container command - either a string or list of arguments.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum Command {
    /// Command as a shell string.
    String(String),

    /// Command as an array of arguments.
    List(Vec<String>),
}

/// Environment variables - either key-value map or list of assignments.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum Environment {
    /// Environment as key-value pairs.
    Map(HashMap<String, String>),

    /// Environment as list of "KEY=VALUE" strings.
    List(Vec<String>),
}

/// Service dependencies with optional conditions.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum DependsOn {
    /// Simple list of service names.
    Simple(Vec<String>),

    /// Dependencies with start conditions.
    Conditional(HashMap<String, DependsCondition>),
}

impl DependsOn {
    /// Returns an iterator over dependency service names.
    pub fn iter(&self) -> Box<dyn Iterator<Item = &String> + '_> {
        match self {
            DependsOn::Simple(list) => Box::new(list.iter()),
            DependsOn::Conditional(map) => Box::new(map.keys()),
        }
    }
}

/// Condition for a service dependency (e.g., "service_healthy").
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DependsCondition {
    /// The condition type: "service_started", "service_healthy", or "service_completed_successfully".
    pub condition: String,
}

/// Health check configuration for determining container readiness.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HealthCheck {
    /// Command to run for health check (e.g., ["CMD", "curl", "-f", "http://localhost/"]).
    pub test: Option<Vec<String>>,

    /// Time between health checks (e.g., "30s").
    pub interval: Option<String>,

    /// Maximum time for check to complete (e.g., "10s").
    pub timeout: Option<String>,

    /// Number of consecutive failures before unhealthy.
    pub retries: Option<u32>,

    /// Initial delay before starting health checks (e.g., "40s").
    pub start_period: Option<String>,
}

/// Deployment configuration for service scaling and resources.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Deploy {
    /// Number of container replicas to run.
    pub replicas: Option<u32>,

    /// Resource limits and reservations.
    pub resources: Option<DeployResources>,
}

/// Resource configuration with limits and reservations.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DeployResources {
    /// Maximum resources the service can use.
    pub limits: Option<ResourceSpec>,

    /// Resources reserved for the service.
    pub reservations: Option<ResourceSpec>,
}

/// CPU and memory resource specification.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ResourceSpec {
    /// CPU limit (e.g., "0.5" for half a CPU).
    pub cpus: Option<String>,

    /// Memory limit (e.g., "512M").
    pub memory: Option<String>,
}

/// Named network configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Network {
    /// Network driver ("bridge", "overlay", "host", etc.).
    pub driver: Option<String>,
}

/// Named volume configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Volume {
    /// Volume driver ("local", "nfs", etc.).
    pub driver: Option<String>,
}

pub mod compose;
pub mod service_graph;

impl ComposeFile {
    /// Parse a compose file from YAML content with variable interpolation.
    ///
    /// # Arguments
    ///
    /// * `content` - Raw YAML content of the compose file.
    /// * `env` - Environment variables for ${VAR} interpolation.
    ///
    /// # Errors
    ///
    /// Returns [`ComposeError::Parse`] for invalid YAML or unresolved variables.
    /// Returns [`ComposeError::Validation`] if the compose file is semantically invalid.
    pub fn parse(content: &str, env: &HashMap<String, String>) -> ComposeResult<Self> {
        let interpolated = interpolate_variables(content, env)?;
        let compose: ComposeFile = serde_yaml::from_str(&interpolated)
            .map_err(|err| ComposeError::Parse(err.to_string()))?;
        compose.validate()?;
        Ok(compose)
    }

    /// Validates the compose file for semantic correctness.
    ///
    /// Checks performed:
    /// - Services map is not empty
    /// - Version is 3.x if specified
    /// - Each service has `image` or `build` specified
    /// - All `depends_on` references exist
    ///
    /// # Errors
    ///
    /// Returns [`ComposeError::Validation`] with details if validation fails.
    pub fn validate(&self) -> ComposeResult<()> {
        if self.services.is_empty() {
            return Err(ComposeError::Validation(
                "services must not be empty".to_string(),
            ));
        }

        if let Some(version) = &self.version {
            if !version.starts_with('3') {
                return Err(ComposeError::Validation(format!(
                    "unsupported compose version: {version}"
                )));
            }
        }

        for (name, service) in &self.services {
            if service.image.is_none() && service.build.is_none() {
                return Err(ComposeError::Validation(format!(
                    "service '{name}' must specify image or build"
                )));
            }

            if let Some(depends_on) = &service.depends_on {
                for dep in depends_on.iter() {
                    if !self.services.contains_key(dep) {
                        return Err(ComposeError::Validation(format!(
                            "service '{name}' depends on unknown service '{dep}'"
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

/// Interpolates ${VAR} and ${VAR:-default} syntax in compose content.
fn interpolate_variables(content: &str, env: &HashMap<String, String>) -> ComposeResult<String> {
    let mut output = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next();
            let mut var = String::new();
            let mut default = None;
            while let Some(next) = chars.next() {
                if next == '}' {
                    break;
                }
                if next == ':' && chars.peek() == Some(&'-') {
                    chars.next();
                    let mut fallback = String::new();
                    for fch in chars.by_ref() {
                        if fch == '}' {
                            break;
                        }
                        fallback.push(fch);
                    }
                    default = Some(fallback);
                    break;
                }
                var.push(next);
            }

            let resolved = resolve_env(&var, env).or(default).unwrap_or_default();
            output.push_str(&resolved);
        } else {
            output.push(ch);
        }
    }

    Ok(output)
}

/// Resolves a variable name to its value, checking provided env and system environment.
fn resolve_env(var: &str, env: &HashMap<String, String>) -> Option<String> {
    if let Some(value) = env.get(var) {
        if !value.is_empty() {
            return Some(value.clone());
        }
    }
    std::env::var(var).ok()
}

#[cfg(test)]
mod tests {
    use super::{ComposeError, ComposeFile, DependsOn};
    use std::collections::HashMap;

    #[test]
    fn parses_compose_file() {
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
        let env = HashMap::new();
        let compose = ComposeFile::parse(content, &env).expect("parse failed");
        assert_eq!(compose.services.len(), 2);
        let web = compose.services.get("web").expect("web missing");
        let deps = web.depends_on.as_ref().expect("depends_on missing");
        match deps {
            DependsOn::Simple(list) => assert_eq!(list, &vec!["db".to_string()]),
            _ => panic!("unexpected depends_on"),
        }
    }

    #[test]
    fn interpolates_env_vars() {
        let content = r#"
version: "3.8"
services:
  api:
    image: ${IMAGE:-busybox:latest}
"#;
        let mut env = HashMap::new();
        env.insert("IMAGE".to_string(), "alpine:3.20".to_string());
        let compose = ComposeFile::parse(content, &env).expect("parse failed");
        let api = compose.services.get("api").expect("api missing");
        assert_eq!(api.image.as_deref(), Some("alpine:3.20"));
    }

    #[test]
    fn rejects_unknown_depends() {
        let content = r#"
version: "3.8"
services:
  api:
    image: alpine:latest
    depends_on:
      - missing
"#;
        let env = HashMap::new();
        let err = ComposeFile::parse(content, &env).expect_err("expected error");
        match err {
            ComposeError::Validation(msg) => assert!(msg.contains("unknown service")),
            _ => panic!("unexpected error"),
        }
    }
}
mod fanout;
pub use fanout::{
    execute_fanout, FanoutAction, FanoutChild, FanoutError, FanoutExecutionError, FanoutOutcome,
    FanoutPlan, FanoutReplayStore, FanoutResult, FanoutStatus, ServiceMutation,
};
