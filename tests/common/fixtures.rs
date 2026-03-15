//! Test fixtures for consistent test data across test suites.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Test fixture representing reusable test data
#[derive(Debug, Clone)]
pub struct Fixture {
    /// Fixture name/identifier
    pub name: String,
    /// Fixture category
    pub category: FixtureCategory,
    /// File contents (for file-based fixtures)
    pub files: HashMap<PathBuf, String>,
    /// Binary data (for image/binary fixtures)
    pub binary: Option<Vec<u8>>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Fixture categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixtureCategory {
    /// Dockerfile fixtures
    Dockerfile,
    /// Compose file fixtures
    Compose,
    /// Container image fixtures
    Image,
    /// Network configuration fixtures
    Network,
    /// Volume/storage fixtures
    Storage,
    /// Configuration file fixtures
    Config,
    /// Malformed/invalid input fixtures for error testing
    Invalid,
}

/// Fixture manager for loading and caching fixtures
pub struct FixtureManager {
    fixtures: HashMap<String, Arc<Fixture>>,
    base_path: PathBuf,
}

impl FixtureManager {
    /// Create a new fixture manager
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            fixtures: HashMap::new(),
            base_path: base_path.into(),
        }
    }

    /// Register a fixture
    pub fn register(&mut self, fixture: Fixture) {
        self.fixtures.insert(fixture.name.clone(), Arc::new(fixture));
    }

    /// Get a fixture by name
    pub fn get(&self, name: &str) -> Option<Arc<Fixture>> {
        self.fixtures.get(name).cloned()
    }

    /// Load fixture into a temporary directory
    pub fn load_to_temp(&self, name: &str) -> std::io::Result<tempfile::TempDir> {
        let fixture = self.get(name)
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Fixture not found: {}", name)
            ))?;

        let temp_dir = tempfile::tempdir()?;

        for (path, content) in &fixture.files {
            let full_path = temp_dir.path().join(path);
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&full_path, content)?;
        }

        Ok(temp_dir)
    }
}

impl Default for FixtureManager {
    fn default() -> Self {
        Self::new("tests/fixtures")
    }
}

/// Common Dockerfile fixtures
pub fn dockerfile_fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            name: "dockerfile_minimal".into(),
            category: FixtureCategory::Dockerfile,
            files: vec![(
                PathBuf::from("Dockerfile"),
                "FROM alpine:3.19\nCMD [\"echo\", \"hello\"]\n".into(),
            )].into_iter().collect(),
            binary: None,
            metadata: vec![("description".into(), "Minimal Dockerfile".into())].into_iter().collect(),
        },
        Fixture {
            name: "dockerfile_multistage".into(),
            category: FixtureCategory::Dockerfile,
            files: vec![(
                PathBuf::from("Dockerfile"),
                r#"FROM alpine:3.19 AS builder
RUN echo "building" > /tmp/output

FROM alpine:3.19
COPY --from=builder /tmp/output /app/output
CMD ["cat", "/app/output"]
"#.into(),
            )].into_iter().collect(),
            binary: None,
            metadata: vec![("description".into(), "Multi-stage Dockerfile".into())].into_iter().collect(),
        },
        Fixture {
            name: "dockerfile_with_arg".into(),
            category: FixtureCategory::Dockerfile,
            files: vec![(
                PathBuf::from("Dockerfile"),
                r#"ARG BASE_IMAGE=alpine:3.19
FROM ${BASE_IMAGE}
ARG VERSION
ENV APP_VERSION=${VERSION}
CMD ["echo", "$APP_VERSION"]
"#.into(),
            )].into_iter().collect(),
            binary: None,
            metadata: vec![("description".into(), "Dockerfile with ARG".into())].into_iter().collect(),
        },
    ]
}

/// Common Compose file fixtures
pub fn compose_fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            name: "compose_simple".into(),
            category: FixtureCategory::Compose,
            files: vec![(
                PathBuf::from("compose.yaml"),
                r#"version: "3.8"
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
"#.into(),
            )].into_iter().collect(),
            binary: None,
            metadata: vec![("description".into(), "Simple compose file".into())].into_iter().collect(),
        },
        Fixture {
            name: "compose_with_deps".into(),
            category: FixtureCategory::Compose,
            files: vec![(
                PathBuf::from("compose.yaml"),
                r#"version: "3.8"
services:
  web:
    image: nginx:alpine
    depends_on:
      - api
      - db
  api:
    image: alpine:3.19
    depends_on:
      - db
  db:
    image: postgres:16-alpine
"#.into(),
            )].into_iter().collect(),
            binary: None,
            metadata: vec![("description".into(), "Compose with dependencies".into())].into_iter().collect(),
        },
        Fixture {
            name: "compose_with_env".into(),
            category: FixtureCategory::Compose,
            files: vec![
                (
                    PathBuf::from("compose.yaml"),
                    r#"version: "3.8"
services:
  app:
    image: ${IMAGE:-alpine:3.19}
    environment:
      - DB_HOST=${DB_HOST:-localhost}
"#.into(),
                ),
                (
                    PathBuf::from(".env"),
                    "IMAGE=nginx:alpine\nDB_HOST=database\n".into(),
                ),
            ].into_iter().collect(),
            binary: None,
            metadata: vec![("description".into(), "Compose with .env".into())].into_iter().collect(),
        },
    ]
}

/// Invalid/malformed fixtures for error testing
pub fn invalid_fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            name: "dockerfile_invalid_instruction".into(),
            category: FixtureCategory::Invalid,
            files: vec![(
                PathBuf::from("Dockerfile"),
                "INVALID_INSTRUCTION something\n".into(),
            )].into_iter().collect(),
            binary: None,
            metadata: vec![("error_type".into(), "parse_error".into())].into_iter().collect(),
        },
        Fixture {
            name: "compose_cyclic_deps".into(),
            category: FixtureCategory::Invalid,
            files: vec![(
                PathBuf::from("compose.yaml"),
                r#"version: "3.8"
services:
  a:
    image: alpine
    depends_on: [b]
  b:
    image: alpine
    depends_on: [a]
"#.into(),
            )].into_iter().collect(),
            binary: None,
            metadata: vec![("error_type".into(), "cyclic_dependency".into())].into_iter().collect(),
        },
        Fixture {
            name: "compose_unknown_dep".into(),
            category: FixtureCategory::Invalid,
            files: vec![(
                PathBuf::from("compose.yaml"),
                r#"version: "3.8"
services:
  web:
    image: alpine
    depends_on: [nonexistent]
"#.into(),
            )].into_iter().collect(),
            binary: None,
            metadata: vec![("error_type".into(), "unknown_dependency".into())].into_iter().collect(),
        },
    ]
}

/// Create a fixture manager with all default fixtures
pub fn default_fixture_manager() -> FixtureManager {
    let mut manager = FixtureManager::default();

    for fixture in dockerfile_fixtures() {
        manager.register(fixture);
    }
    for fixture in compose_fixtures() {
        manager.register(fixture);
    }
    for fixture in invalid_fixtures() {
        manager.register(fixture);
    }

    manager
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixture_manager_load() {
        let manager = default_fixture_manager();
        let fixture = manager.get("dockerfile_minimal");
        assert!(fixture.is_some());
    }

    #[test]
    fn test_fixture_load_to_temp() {
        let manager = default_fixture_manager();
        let temp_dir = manager.load_to_temp("dockerfile_minimal").expect("load");
        assert!(temp_dir.path().join("Dockerfile").exists());
    }
}
