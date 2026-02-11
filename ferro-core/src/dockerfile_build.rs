use crate::image_manifest::{
    Descriptor, ImageManifest, OCI_IMAGE_CONFIG_MEDIA_TYPE, OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE,
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
};
use crate::image_store::LocalImageStore;
use crate::image_tagging::canonicalize_reference;
use serde_json::json;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use tar::Builder;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DockerfileBuildError {
    #[error("dockerfile not found: {0}")]
    MissingDockerfile(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("image store error: {0}")]
    Store(#[from] crate::image_store::ImageStoreError),
    #[error("invalid image reference: {0}")]
    Reference(#[from] crate::image_tagging::ImageTaggingError),
    #[error("unsupported Dockerfile instruction: {0}")]
    Unsupported(String),
    #[error("invalid Dockerfile: {0}")]
    Invalid(String),
}

pub struct BuildResult {
    pub reference: String,
    pub layer_digest: String,
    pub config_digest: String,
}

pub fn build_from_dockerfile(
    dockerfile_path: &Path,
    tag: Option<&str>,
    runtime_dir: &Path,
) -> Result<BuildResult, DockerfileBuildError> {
    if !dockerfile_path.exists() {
        return Err(DockerfileBuildError::MissingDockerfile(
            dockerfile_path.display().to_string(),
        ));
    }

    let dockerfile = fs::read_to_string(dockerfile_path)?;
    let instructions = parse_instructions(&dockerfile)?;
    let mut from_scratch = false;
    let mut healthcheck = None;

    for instr in &instructions {
        match instr.keyword.as_str() {
            "FROM" => {
                if instr.value.eq_ignore_ascii_case("scratch") {
                    from_scratch = true;
                } else {
                    return Err(DockerfileBuildError::Unsupported(
                        "only FROM scratch is supported".to_string(),
                    ));
                }
            }
            "COPY" => {}
            "CMD" => {}
            "HEALTHCHECK" => {
                healthcheck = parse_healthcheck(&instr.value)?;
            }
            other => {
                return Err(DockerfileBuildError::Unsupported(format!(
                    "instruction {other} is not supported"
                )));
            }
        }
    }

    if !from_scratch {
        return Err(DockerfileBuildError::Invalid(
            "missing FROM scratch".to_string(),
        ));
    }

    let context_dir = dockerfile_path
        .parent()
        .ok_or_else(|| DockerfileBuildError::Invalid("invalid dockerfile path".to_string()))?;
    let layer_bytes = build_context_layer(context_dir, dockerfile_path)?;
    let layer_digest = format!("sha256:{}", blake3::hash(&layer_bytes).to_hex());
    let layer_size = layer_bytes.len() as i64;

    let config_json = build_config_json(healthcheck);
    let config_bytes = config_json.as_bytes();
    let config_digest = format!("sha256:{}", blake3::hash(config_bytes).to_hex());

    let manifest = ImageManifest {
        schema_version: 2,
        media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_string(),
        config: Descriptor {
            media_type: OCI_IMAGE_CONFIG_MEDIA_TYPE.to_string(),
            digest: config_digest.clone(),
            size: config_bytes.len() as i64,
            urls: Vec::new(),
            annotations: None,
            artifact_type: None,
            platform: None,
        },
        layers: vec![Descriptor {
            media_type: OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string(),
            digest: layer_digest.clone(),
            size: layer_size,
            urls: Vec::new(),
            annotations: None,
            artifact_type: None,
            platform: None,
        }],
        artifact_type: None,
        subject: None,
        annotations: Default::default(),
    };
    let manifest_json = serde_json::to_string(&manifest).map_err(|err| {
        io::Error::new(io::ErrorKind::Other, err.to_string())
    })?;

    let reference = canonicalize_reference(tag.unwrap_or("local/build:latest"))?;
    let store = LocalImageStore::open(runtime_dir.join("images"))?;
    store.put_reference(
        &reference,
        &config_digest,
        OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        &manifest_json,
    )?;

    write_blob(runtime_dir, &layer_digest, &layer_bytes)?;
    write_config(runtime_dir, &config_digest, config_bytes)?;

    Ok(BuildResult {
        reference,
        layer_digest,
        config_digest,
    })
}

fn build_context_layer(
    context_dir: &Path,
    dockerfile_path: &Path,
) -> Result<Vec<u8>, DockerfileBuildError> {
    let mut tar_builder = Builder::new(Vec::new());
    add_directory(
        &mut tar_builder,
        context_dir,
        context_dir,
        dockerfile_path,
    )?;
    let tar_bytes = tar_builder.into_inner().map_err(|err| {
        io::Error::new(io::ErrorKind::Other, err.to_string())
    })?;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes)?;
    let gzip_bytes = encoder.finish()?;
    Ok(gzip_bytes)
}

fn add_directory(
    builder: &mut Builder<Vec<u8>>,
    base: &Path,
    path: &Path,
    dockerfile_path: &Path,
) -> Result<(), DockerfileBuildError> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let relative = entry_path
            .strip_prefix(base)
            .unwrap_or(&entry_path)
            .to_path_buf();
        if entry_path == dockerfile_path {
            continue;
        }
        if relative.components().next().map(|c| c.as_os_str()) == Some(".git".as_ref()) {
            continue;
        }
        if relative.components().next().map(|c| c.as_os_str()) == Some(".ferrocrate".as_ref()) {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            add_directory(builder, base, &entry_path, dockerfile_path)?;
        } else if file_type.is_file() {
            builder
                .append_path_with_name(&entry_path, &relative)
                .map_err(|err| DockerfileBuildError::Io(err))?;
        }
    }
    Ok(())
}

fn build_config_json(healthcheck: Option<HealthcheckSpec>) -> String {
    let health = healthcheck.map(|spec| {
        json!({
            "Test": spec.test,
            "Interval": spec.interval_nanos,
            "Timeout": spec.timeout_nanos,
            "Retries": spec.retries,
            "StartPeriod": spec.start_period_nanos
        })
    });

    json!({
        "created": "1970-01-01T00:00:00Z",
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Env": [],
            "Cmd": [],
            "Healthcheck": health
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": []
        },
        "history": []
    })
    .to_string()
}

fn write_blob(runtime_dir: &Path, digest: &str, bytes: &[u8]) -> Result<(), DockerfileBuildError> {
    let blob_root = runtime_dir.join("images").join("blobs");
    fs::create_dir_all(&blob_root)?;
    let file_name = digest.replace(':', "_");
    let path = blob_root.join(file_name);
    fs::write(path, bytes)?;
    Ok(())
}

fn write_config(
    runtime_dir: &Path,
    digest: &str,
    bytes: &[u8],
) -> Result<(), DockerfileBuildError> {
    let config_root = runtime_dir.join("images").join("configs");
    fs::create_dir_all(&config_root)?;
    let file_name = digest.replace(':', "_");
    let path = config_root.join(file_name);
    fs::write(path, bytes)?;
    Ok(())
}

#[derive(Debug)]
struct Instruction {
    keyword: String,
    value: String,
}

fn parse_instructions(contents: &str) -> Result<Vec<Instruction>, DockerfileBuildError> {
    let mut out = Vec::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let keyword = parts.next().unwrap_or("").trim().to_uppercase();
        let value = parts.next().unwrap_or("").trim().to_string();
        if keyword.is_empty() {
            continue;
        }
        out.push(Instruction { keyword, value });
    }
    Ok(out)
}

#[derive(Debug)]
struct HealthcheckSpec {
    test: Vec<String>,
    interval_nanos: u64,
    timeout_nanos: u64,
    retries: u32,
    start_period_nanos: u64,
}

fn parse_healthcheck(raw: &str) -> Result<Option<HealthcheckSpec>, DockerfileBuildError> {
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("NONE") {
        return Ok(None);
    }

    let mut tokens = trimmed.split_whitespace().peekable();
    let mut interval = None;
    let mut timeout = None;
    let mut retries = None;
    let mut start_period = None;

    while let Some(tok) = tokens.peek().cloned() {
        if !tok.starts_with("--") {
            break;
        }
        let tok = tokens.next().unwrap();
        let (key, val) = tok
            .trim_start_matches("--")
            .split_once('=')
            .ok_or_else(|| DockerfileBuildError::Invalid("invalid HEALTHCHECK flag".to_string()))?;
        match key {
            "interval" => interval = parse_duration_to_nanos(val),
            "timeout" => timeout = parse_duration_to_nanos(val),
            "retries" => retries = val.parse::<u32>().ok(),
            "start-period" => start_period = parse_duration_to_nanos(val),
            _ => {}
        }
    }

    let mode = tokens
        .next()
        .ok_or_else(|| DockerfileBuildError::Invalid("missing HEALTHCHECK mode".to_string()))?;
    let rest = tokens.collect::<Vec<_>>().join(" ");
    let test = if mode.eq_ignore_ascii_case("CMD") {
        rest.split_whitespace().map(|s| s.to_string()).collect()
    } else if mode.eq_ignore_ascii_case("CMD-SHELL") {
        vec!["/bin/sh".to_string(), "-c".to_string(), rest]
    } else {
        return Err(DockerfileBuildError::Invalid(
            "unsupported HEALTHCHECK mode".to_string(),
        ));
    };

    Ok(Some(HealthcheckSpec {
        test,
        interval_nanos: interval.unwrap_or(30_000_000_000),
        timeout_nanos: timeout.unwrap_or(5_000_000_000),
        retries: retries.unwrap_or(3),
        start_period_nanos: start_period.unwrap_or(0),
    }))
}

fn parse_duration_to_nanos(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.ends_with("ms") {
        trimmed
            .trim_end_matches("ms")
            .parse::<u64>()
            .ok()
            .map(|v| v * 1_000_000)
    } else if trimmed.ends_with('s') {
        trimmed
            .trim_end_matches('s')
            .parse::<u64>()
            .ok()
            .map(|v| v * 1_000_000_000)
    } else if trimmed.ends_with('m') {
        trimmed
            .trim_end_matches('m')
            .parse::<u64>()
            .ok()
            .map(|v| v * 60 * 1_000_000_000)
    } else if trimmed.ends_with('h') {
        trimmed
            .trim_end_matches('h')
            .parse::<u64>()
            .ok()
            .map(|v| v * 60 * 60 * 1_000_000_000)
    } else {
        trimmed
            .parse::<u64>()
            .ok()
            .map(|v| v * 1_000_000_000)
    }
}

#[cfg(test)]
mod tests {
    use super::build_from_dockerfile;
    use crate::image_fetch::resolve_layer_paths;
    use std::fs;

    #[test]
    fn builds_minimal_dockerfile() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\nCOPY . /\n").expect("write");
        fs::write(temp.path().join("hello.txt"), "hi").expect("write file");

        let runtime_dir = temp.path().join("runtime");
        let result = build_from_dockerfile(&dockerfile, Some("local/test:latest"), &runtime_dir)
            .expect("build");
        let layers = resolve_layer_paths(&runtime_dir, &result.reference).expect("layers");
        assert_eq!(layers.len(), 1);
        assert!(layers[0].exists());
    }
}
