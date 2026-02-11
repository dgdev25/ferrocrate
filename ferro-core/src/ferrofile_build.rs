use crate::dockerfile_build::{build_from_dockerfile, BuildResult, DockerfileBuildError};
use serde::Deserialize;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FerrofileBuildError {
    #[error("ferrofile not found: {0}")]
    Missing(String),
    #[error("invalid ferrofile: {0}")]
    Invalid(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("dockerfile build error: {0}")]
    Dockerfile(#[from] DockerfileBuildError),
    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
}

#[derive(Debug, Deserialize)]
struct Ferrofile {
    build: Option<BuildSpec>,
}

#[derive(Debug, Deserialize)]
struct BuildSpec {
    context: Option<String>,
    dockerfile: Option<String>,
    tag: Option<String>,
}

pub fn build_from_ferrofile(
    ferrofile_path: &Path,
    runtime_dir: &Path,
) -> Result<BuildResult, FerrofileBuildError> {
    if !ferrofile_path.exists() {
        return Err(FerrofileBuildError::Missing(
            ferrofile_path.display().to_string(),
        ));
    }
    let contents = fs::read_to_string(ferrofile_path)?;
    let ferrofile: Ferrofile = toml::from_str(&contents)?;
    let build = ferrofile
        .build
        .ok_or_else(|| FerrofileBuildError::Invalid("missing [build] section".to_string()))?;

    let base_dir = ferrofile_path
        .parent()
        .ok_or_else(|| FerrofileBuildError::Invalid("invalid ferrofile path".to_string()))?;
    let context_dir = build
        .context
        .as_deref()
        .map(|path| base_dir.join(path))
        .unwrap_or_else(|| base_dir.to_path_buf());
    let dockerfile_path = build
        .dockerfile
        .as_deref()
        .map(|path| context_dir.join(path))
        .unwrap_or_else(|| context_dir.join("Dockerfile"));

    let tag = build.tag.as_deref();
    build_from_dockerfile(&dockerfile_path, tag, runtime_dir).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::build_from_ferrofile;
    use std::fs;

    #[test]
    fn builds_from_ferrofile() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("ferrofile.toml"),
            r#"[build]
tag = "local/ferrofile:latest"
"#,
        )
        .expect("write");
        fs::write(temp.path().join("Dockerfile"), "FROM scratch\nCOPY . /\n").expect("write");
        fs::write(temp.path().join("hello.txt"), "hi").expect("write");

        let runtime_dir = temp.path().join("runtime");
        let result = build_from_ferrofile(&temp.path().join("ferrofile.toml"), &runtime_dir)
            .expect("build");
        assert_eq!(result.reference, "registry-1.docker.io/local/ferrofile:latest");
    }
}
