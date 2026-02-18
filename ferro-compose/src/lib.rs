use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    #[error("compose parse error: {0}")]
    Parse(String),
    #[error("compose validation error: {0}")]
    Validation(String),
}

pub type ComposeResult<T> = Result<T, ComposeError>;

#[derive(Debug, Deserialize, Clone)]
pub struct ComposeFile {
    pub version: Option<String>,
    pub services: HashMap<String, Service>,
    pub networks: Option<HashMap<String, Network>>,
    pub volumes: Option<HashMap<String, Volume>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Service {
    pub image: Option<String>,
    pub build: Option<Build>,
    pub command: Option<Command>,
    pub entrypoint: Option<String>,
    pub environment: Option<Environment>,
    pub env_file: Option<Vec<String>>,
    pub ports: Option<Vec<String>>,
    pub volumes: Option<Vec<String>>,
    pub networks: Option<Vec<String>>,
    #[serde(rename = "network_mode")]
    pub network_mode: Option<String>,
    pub depends_on: Option<DependsOn>,
    pub restart: Option<String>,
    pub healthcheck: Option<HealthCheck>,
    pub deploy: Option<Deploy>,
    pub labels: Option<HashMap<String, String>>,
    pub profiles: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Build {
    pub context: Option<String>,
    pub dockerfile: Option<String>,
    pub args: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum Command {
    String(String),
    List(Vec<String>),
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum Environment {
    Map(HashMap<String, String>),
    List(Vec<String>),
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum DependsOn {
    Simple(Vec<String>),
    Conditional(HashMap<String, DependsCondition>),
}

impl DependsOn {
    pub fn iter(&self) -> Box<dyn Iterator<Item = &String> + '_> {
        match self {
            DependsOn::Simple(list) => Box::new(list.iter()),
            DependsOn::Conditional(map) => Box::new(map.keys()),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct DependsCondition {
    pub condition: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HealthCheck {
    pub test: Option<Vec<String>>,
    pub interval: Option<String>,
    pub timeout: Option<String>,
    pub retries: Option<u32>,
    pub start_period: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Deploy {
    pub replicas: Option<u32>,
    pub resources: Option<DeployResources>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DeployResources {
    pub limits: Option<ResourceSpec>,
    pub reservations: Option<ResourceSpec>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ResourceSpec {
    pub cpus: Option<String>,
    pub memory: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Network {
    pub driver: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Volume {
    pub driver: Option<String>,
}

pub mod compose;
pub mod service_graph;

impl ComposeFile {
    pub fn parse(content: &str, env: &HashMap<String, String>) -> ComposeResult<Self> {
        let interpolated = interpolate_variables(content, env)?;
        let compose: ComposeFile = serde_yaml::from_str(&interpolated)
            .map_err(|err| ComposeError::Parse(err.to_string()))?;
        compose.validate()?;
        Ok(compose)
    }

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
