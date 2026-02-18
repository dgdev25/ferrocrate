use crate::ai_runtime::AiRuntimeConfig;
use crate::dockerfile_build::{
    build_from_dockerfile_with_compression, build_from_dockerfile_with_store_and_compression,
    BuildResult, DockerfileBuildError,
};
use crate::image_store::LocalImageStore;
use crate::layer_compression::CompressionFormat;
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
    ai_runtime: Option<AiRuntimeConfig>,
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
    compression: CompressionFormat,
) -> Result<BuildResult, FerrofileBuildError> {
    build_from_ferrofile_with_store(ferrofile_path, runtime_dir, compression, None)
}

pub fn build_from_ferrofile_with_store(
    ferrofile_path: &Path,
    runtime_dir: &Path,
    compression: CompressionFormat,
    store: Option<&LocalImageStore>,
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
    let result = if let Some(store) = store {
        build_from_dockerfile_with_store_and_compression(
            &dockerfile_path,
            tag,
            runtime_dir,
            compression,
            store,
        )
    } else {
        build_from_dockerfile_with_compression(&dockerfile_path, tag, runtime_dir, compression)
    };
    result.map_err(Into::into)
}

/// Parses the `[ai_runtime]` section from a ferrofile.toml, if present.
pub fn ai_runtime_config_from_ferrofile(
    ferrofile_path: &Path,
) -> Result<Option<AiRuntimeConfig>, FerrofileBuildError> {
    if !ferrofile_path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(ferrofile_path)?;
    let ferrofile: Ferrofile = toml::from_str(&contents)?;
    Ok(ferrofile.ai_runtime)
}

#[cfg(test)]
mod tests {
    use super::build_from_ferrofile;
    use crate::layer_compression::CompressionFormat;
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
        let result = build_from_ferrofile(
            &temp.path().join("ferrofile.toml"),
            &runtime_dir,
            CompressionFormat::Gzip,
        )
        .expect("build");
        assert_eq!(
            result.reference,
            "registry-1.docker.io/local/ferrofile:latest"
        );
    }
}
