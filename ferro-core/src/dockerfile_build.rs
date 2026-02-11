use crate::image_manifest::{
    Descriptor, ImageManifest, OCI_IMAGE_CONFIG_MEDIA_TYPE, OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE,
    OCI_IMAGE_LAYER_ZSTD_MEDIA_TYPE, OCI_IMAGE_MANIFEST_MEDIA_TYPE,
};
use crate::image_fetch::{pull_image_with_store, resolve_layer_paths_with_store};
use crate::image_manifest::parse_image_manifest;
use crate::image_store::LocalImageStore;
use crate::image_tagging::{canonicalize_reference, resolve_reference};
use crate::rootfs::{apply_layer_tar, construct_rootfs_with_dedup};
use crate::layer_compression::{
    CompressionFormat, LayerCompressionError, compress_bytes_gzip, compress_bytes_zstd,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
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
    #[error("compression error: {0}")]
    Compression(#[from] LayerCompressionError),
}

pub struct BuildResult {
    pub reference: String,
    pub layer_digest: String,
    pub config_digest: String,
}

#[derive(Debug, Clone)]
struct BaseImageInfo {
    layers: Vec<PathBuf>,
    descriptors: Vec<Descriptor>,
    digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BuildCacheEntry {
    layer_digest: String,
    layer_size: i64,
    layer_media_type: String,
    config_digest: String,
    config_json: String,
    manifest_json: String,
}

pub fn build_from_dockerfile(
    dockerfile_path: &Path,
    tag: Option<&str>,
    runtime_dir: &Path,
) -> Result<BuildResult, DockerfileBuildError> {
    build_from_dockerfile_with_compression(dockerfile_path, tag, runtime_dir, CompressionFormat::Gzip)
}

pub fn build_from_dockerfile_with_compression(
    dockerfile_path: &Path,
    tag: Option<&str>,
    runtime_dir: &Path,
    compression: CompressionFormat,
) -> Result<BuildResult, DockerfileBuildError> {
    let store = LocalImageStore::open(runtime_dir.join("images"))?;
    build_from_dockerfile_with_store_and_compression(
        dockerfile_path,
        tag,
        runtime_dir,
        compression,
        &store,
    )
}

pub fn build_from_dockerfile_with_store_and_compression(
    dockerfile_path: &Path,
    tag: Option<&str>,
    runtime_dir: &Path,
    compression: CompressionFormat,
    store: &LocalImageStore,
) -> Result<BuildResult, DockerfileBuildError> {
    if !dockerfile_path.exists() {
        return Err(DockerfileBuildError::MissingDockerfile(
            dockerfile_path.display().to_string(),
        ));
    }

    let dockerfile = fs::read_to_string(dockerfile_path)?;
    let stages = parse_stages(&dockerfile)?;
    let context_dir = dockerfile_path
        .parent()
        .ok_or_else(|| DockerfileBuildError::Invalid("invalid dockerfile path".to_string()))?;
    let context_hash = hash_context_dir(context_dir, dockerfile_path)?;
    let mut base_infos = Vec::new();
    for stage in stages.iter() {
        let base_info = resolve_base_image(store, runtime_dir, &stage.base)?;
        base_infos.push(base_info);
    }
    let cache_key = build_cache_key(&dockerfile, compression, &context_hash, &base_infos);
    let mut cache = load_build_cache(runtime_dir)?;
    if let Some(entry) = cache.get(&cache_key).cloned() {
        let layer_path = blob_path(runtime_dir, &entry.layer_digest);
        let config_path = config_path(runtime_dir, &entry.config_digest);
        if layer_path.exists() && config_path.exists() {
            let reference = canonicalize_reference(tag.unwrap_or("local/build:latest"))?;
            store.put_reference(
                &reference,
                &entry.config_digest,
                OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                &entry.manifest_json,
            )?;
            return Ok(BuildResult {
                reference,
                layer_digest: entry.layer_digest,
                config_digest: entry.config_digest,
            });
        }
    }
    let mut stage_roots: Vec<PathBuf> = Vec::new();
    let mut stage_names: HashMap<String, PathBuf> = HashMap::new();
    let mut final_result = None;

    for (idx, stage) in stages.iter().enumerate() {
        let base_info = &base_infos[idx];
        let base_layers = &base_info.layers;
        let base_descriptors = base_info.descriptors.clone();
        let stage_root = runtime_dir.join("build").join(format!("stage-{idx}"));
        if stage_root.exists() {
            let _ = fs::remove_dir_all(&stage_root);
        }
        let cas_root = runtime_dir.join("images").join("cas").join("blake3");
        if !base_layers.is_empty() {
            construct_rootfs_with_dedup(&stage_root, base_layers, &cas_root)
                .map_err(|err| DockerfileBuildError::Invalid(err.to_string()))?;
        } else {
            fs::create_dir_all(&stage_root)?;
        }

        let context_root = create_build_dir(runtime_dir, &format!("context-{idx}"))?;
        copy_context_dir(context_dir, &context_root, dockerfile_path)?;

        for copy in &stage.copy_from {
            let source_root = resolve_stage_root(&stage_roots, &stage_names, &copy.from)
                .ok_or_else(|| DockerfileBuildError::Invalid(format!(
                    "unknown COPY --from stage: {}",
                    copy.from
                )))?;
            let source = source_root.join(copy.src.trim_start_matches('/'));
            let dest = context_root.join(copy.dest.trim_start_matches('/'));
            copy_path_recursive(&source, &dest)?;
        }

        let (layer_bytes, layer_media_type) =
            build_context_layer_from_dir(&context_root, compression)?;
        let layer_digest = format!("sha256:{}", blake3::hash(&layer_bytes).to_hex());
        let layer_size = layer_bytes.len() as i64;
        write_blob(runtime_dir, &layer_digest, &layer_bytes)?;

        let layer_path = blob_path(runtime_dir, &layer_digest);
        apply_layer_tar(&stage_root, &layer_path)
            .map_err(|err| DockerfileBuildError::Invalid(err.to_string()))?;

        stage_roots.push(stage_root.clone());
        if let Some(name) = stage.name.as_ref() {
            stage_names.insert(name.to_string(), stage_root.clone());
        }

        if idx == stages.len() - 1 {
            let config_json = build_config_json(stage.healthcheck.clone());
            let config_bytes = config_json.as_bytes();
            let config_digest = format!("sha256:{}", blake3::hash(config_bytes).to_hex());

            let mut layers = base_descriptors;
            layers.push(Descriptor {
                media_type: layer_media_type.clone(),
                digest: layer_digest.clone(),
                size: layer_size,
                urls: Vec::new(),
                annotations: None,
                artifact_type: None,
                platform: None,
            });

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
                layers,
                artifact_type: None,
                subject: None,
                annotations: Default::default(),
            };
            let manifest_json = serde_json::to_string(&manifest).map_err(|err| {
                io::Error::new(io::ErrorKind::Other, err.to_string())
            })?;

            let reference = canonicalize_reference(tag.unwrap_or("local/build:latest"))?;
            store.put_reference(
                &reference,
                &config_digest,
                OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                &manifest_json,
            )?;

            write_config(runtime_dir, &config_digest, config_bytes)?;

            cache.insert(
                cache_key.clone(),
                BuildCacheEntry {
                    layer_digest: layer_digest.clone(),
                    layer_size,
                    layer_media_type,
                    config_digest: config_digest.clone(),
                    config_json: config_json.clone(),
                    manifest_json: manifest_json.clone(),
                },
            );
            save_build_cache(runtime_dir, &cache)?;

            final_result = Some(BuildResult {
                reference,
                layer_digest,
                config_digest,
            });
        }
    }

    final_result.ok_or_else(|| DockerfileBuildError::Invalid("no stages built".to_string()))
}

fn build_context_layer_from_dir(
    context_dir: &Path,
    compression: CompressionFormat,
) -> Result<(Vec<u8>, String), DockerfileBuildError> {
    let mut tar_builder = Builder::new(Vec::new());
    add_directory(&mut tar_builder, context_dir, context_dir, None)?;
    let tar_bytes = tar_builder.into_inner().map_err(|err| {
        io::Error::new(io::ErrorKind::Other, err.to_string())
    })?;
    match compression {
        CompressionFormat::Gzip => {
            let gzip_bytes = compress_bytes_gzip(&tar_bytes)?;
            Ok((gzip_bytes, OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string()))
        }
        CompressionFormat::Zstd => {
            let zstd_bytes = compress_bytes_zstd(&tar_bytes)?;
            Ok((zstd_bytes, OCI_IMAGE_LAYER_ZSTD_MEDIA_TYPE.to_string()))
        }
        CompressionFormat::None => Err(DockerfileBuildError::Unsupported(
            "uncompressed layers are not supported".to_string(),
        )),
    }
}

fn add_directory(
    builder: &mut Builder<Vec<u8>>,
    base: &Path,
    path: &Path,
    dockerfile_path: Option<&Path>,
) -> Result<(), DockerfileBuildError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)? {
        entries.push(entry?);
    }
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let entry_path = entry.path();
        let relative = entry_path
            .strip_prefix(base)
            .unwrap_or(&entry_path)
            .to_path_buf();
        if let Some(dockerfile_path) = dockerfile_path {
            if entry_path == dockerfile_path {
                continue;
            }
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
    write_cas_blob(runtime_dir, "blobs", digest, bytes)
}

fn write_config(
    runtime_dir: &Path,
    digest: &str,
    bytes: &[u8],
) -> Result<(), DockerfileBuildError> {
    write_cas_blob(runtime_dir, "configs", digest, bytes)
}

fn write_cas_blob(
    runtime_dir: &Path,
    subdir: &str,
    digest: &str,
    bytes: &[u8],
) -> Result<(), DockerfileBuildError> {
    let cas_root = runtime_dir.join("images").join("cas").join("blake3");
    fs::create_dir_all(&cas_root)?;
    let hash = blake3::hash(bytes).to_hex().to_string();
    let cas_path = cas_root.join(hash);
    if !cas_path.exists() {
        fs::write(&cas_path, bytes)?;
    }

    let root = runtime_dir.join("images").join(subdir);
    fs::create_dir_all(&root)?;
    let file_name = digest.replace(':', "_");
    let path = root.join(file_name);
    if path.exists() {
        return Ok(());
    }
    if fs::hard_link(&cas_path, &path).is_err() {
        fs::copy(&cas_path, &path)?;
    }
    Ok(())
}

fn build_cache_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("images").join("build-cache.json")
}

fn load_build_cache(
    runtime_dir: &Path,
) -> Result<HashMap<String, BuildCacheEntry>, DockerfileBuildError> {
    let path = build_cache_path(runtime_dir);
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let bytes = fs::read(&path)?;
    let cache = serde_json::from_slice::<HashMap<String, BuildCacheEntry>>(&bytes)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    Ok(cache)
}

fn save_build_cache(
    runtime_dir: &Path,
    cache: &HashMap<String, BuildCacheEntry>,
) -> Result<(), DockerfileBuildError> {
    let path = build_cache_path(runtime_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(cache)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    fs::write(&path, bytes)?;
    Ok(())
}

fn build_cache_key(
    dockerfile: &str,
    compression: CompressionFormat,
    context_hash: &str,
    base_infos: &[BaseImageInfo],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(dockerfile.as_bytes());
    hasher.update(context_hash.as_bytes());
    hasher.update(format!("{compression:?}").as_bytes());
    for info in base_infos {
        if let Some(digest) = &info.digest {
            hasher.update(digest.as_bytes());
        }
    }
    hasher.finalize().to_hex().to_string()
}

fn hash_context_dir(
    context_dir: &Path,
    dockerfile_path: &Path,
) -> Result<String, DockerfileBuildError> {
    let mut files = Vec::new();
    collect_context_files(context_dir, context_dir, dockerfile_path, &mut files)?;
    files.sort();
    let mut hasher = blake3::Hasher::new();
    for rel_path in files {
        let full_path = context_dir.join(&rel_path);
        hasher.update(rel_path.to_string_lossy().as_bytes());
        let bytes = fs::read(&full_path)?;
        hasher.update(&bytes);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn collect_context_files(
    base: &Path,
    path: &Path,
    dockerfile_path: &Path,
    out: &mut Vec<PathBuf>,
) -> Result<(), DockerfileBuildError> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path == dockerfile_path {
            continue;
        }
        let relative = entry_path
            .strip_prefix(base)
            .unwrap_or(&entry_path)
            .to_path_buf();
        if relative.components().next().map(|c| c.as_os_str()) == Some(".git".as_ref()) {
            continue;
        }
        if relative.components().next().map(|c| c.as_os_str()) == Some(".ferrocrate".as_ref()) {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_context_files(base, &entry_path, dockerfile_path, out)?;
        } else if file_type.is_file() {
            out.push(relative);
        }
    }
    Ok(())
}

fn config_path(runtime_dir: &Path, digest: &str) -> PathBuf {
    runtime_dir
        .join("images")
        .join("configs")
        .join(digest.replace(':', "_"))
}

#[derive(Debug, Clone)]
struct CopyFromSpec {
    from: String,
    src: String,
    dest: String,
}

#[derive(Debug, Clone)]
struct StageSpec {
    base: String,
    name: Option<String>,
    copy_from: Vec<CopyFromSpec>,
    healthcheck: Option<HealthcheckSpec>,
}

fn parse_stages(contents: &str) -> Result<Vec<StageSpec>, DockerfileBuildError> {
    let mut stages = Vec::new();
    let mut current: Option<StageSpec> = None;

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

        if keyword == "FROM" {
            if let Some(stage) = current.take() {
                stages.push(stage);
            }
            let (base, name) = parse_from(&value)?;
            current = Some(StageSpec {
                base,
                name,
                copy_from: Vec::new(),
                healthcheck: None,
            });
            continue;
        }

        let stage = current.as_mut().ok_or_else(|| {
            DockerfileBuildError::Invalid("missing FROM instruction".to_string())
        })?;

        match keyword.as_str() {
            "COPY" => {
                if let Some(copy) = parse_copy_from(&value)? {
                    stage.copy_from.push(copy);
                }
            }
            "CMD" => {}
            "HEALTHCHECK" => {
                stage.healthcheck = parse_healthcheck(&value)?;
            }
            other => {
                return Err(DockerfileBuildError::Unsupported(format!(
                    "instruction {other} is not supported"
                )));
            }
        }
    }

    if let Some(stage) = current.take() {
        stages.push(stage);
    }

    if stages.is_empty() {
        return Err(DockerfileBuildError::Invalid(
            "missing FROM instruction".to_string(),
        ));
    }

    Ok(stages)
}

fn parse_from(value: &str) -> Result<(String, Option<String>), DockerfileBuildError> {
    let parts = value.split_whitespace().collect::<Vec<_>>();
    if parts.is_empty() {
        return Err(DockerfileBuildError::Invalid(
            "invalid FROM instruction".to_string(),
        ));
    }
    if parts.len() >= 3 && parts[1].eq_ignore_ascii_case("AS") {
        return Ok((parts[0].to_string(), Some(parts[2].to_string())));
    }
    Ok((parts[0].to_string(), None))
}

fn parse_copy_from(value: &str) -> Result<Option<CopyFromSpec>, DockerfileBuildError> {
    let tokens = value.split_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        return Ok(None);
    }
    let mut idx = 0;
    let mut from = None;
    if tokens[idx].starts_with("--from=") {
        from = Some(tokens[idx].trim_start_matches("--from=").to_string());
        idx += 1;
    } else if tokens[idx] == "--from" {
        if tokens.len() <= idx + 1 {
            return Err(DockerfileBuildError::Invalid(
                "COPY --from missing stage".to_string(),
            ));
        }
        from = Some(tokens[idx + 1].to_string());
        idx += 2;
    }

    let Some(from) = from else {
        return Ok(None);
    };

    if tokens.len() <= idx + 1 {
        return Err(DockerfileBuildError::Invalid(
            "COPY --from requires src and dest".to_string(),
        ));
    }
    Ok(Some(CopyFromSpec {
        from,
        src: tokens[idx].to_string(),
        dest: tokens[idx + 1].to_string(),
    }))
}

#[derive(Debug, Clone)]
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

fn resolve_base_image(
    store: &LocalImageStore,
    runtime_dir: &Path,
    base: &str,
) -> Result<BaseImageInfo, DockerfileBuildError> {
    if base.eq_ignore_ascii_case("scratch") {
        return Ok(BaseImageInfo {
            layers: Vec::new(),
            descriptors: Vec::new(),
            digest: None,
        });
    }

    let _ = pull_image_with_store(runtime_dir, base, store);
    let record = resolve_reference(store, base)
        .map_err(DockerfileBuildError::Reference)?
        .ok_or_else(|| DockerfileBuildError::Invalid(format!("base image not found: {base}")))?;
    let manifest = parse_image_manifest(&record.manifest_json)
        .map_err(|err| DockerfileBuildError::Invalid(err.to_string()))?;
    let layers = resolve_layer_paths_with_store(runtime_dir, base, store)
        .map_err(|err| DockerfileBuildError::Invalid(err.to_string()))?;
    Ok(BaseImageInfo {
        layers,
        descriptors: manifest.layers,
        digest: Some(record.digest),
    })
}

fn resolve_stage_root(
    roots: &[PathBuf],
    names: &HashMap<String, PathBuf>,
    from: &str,
) -> Option<PathBuf> {
    if let Ok(idx) = from.parse::<usize>() {
        return roots.get(idx).cloned();
    }
    names.get(from).cloned()
}

fn create_build_dir(_runtime_dir: &Path, name: &str) -> Result<PathBuf, DockerfileBuildError> {
    let root = std::env::temp_dir().join("ferrocrate-build");
    fs::create_dir_all(&root)?;
    let candidate = root.join(format!("{}-{}", name, std::process::id()));
    if candidate.exists() {
        let _ = fs::remove_dir_all(&candidate);
    }
    fs::create_dir_all(&candidate)?;
    Ok(candidate)
}

fn copy_context_dir(
    src: &Path,
    dst: &Path,
    dockerfile_path: &Path,
) -> Result<(), DockerfileBuildError> {
    fs::create_dir_all(dst)?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(src)? {
        entries.push(entry?);
    }
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(src).unwrap_or(&path);
        if path == dockerfile_path {
            continue;
        }
        if relative.components().next().map(|c| c.as_os_str()) == Some(".git".as_ref()) {
            continue;
        }
        if relative.components().next().map(|c| c.as_os_str()) == Some(".ferrocrate".as_ref()) {
            continue;
        }
        let target = dst.join(relative);
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_context_dir(&path, &target, dockerfile_path)?;
        } else if file_type.is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

fn copy_path_recursive(src: &Path, dst: &Path) -> Result<(), DockerfileBuildError> {
    let metadata = fs::metadata(src)?;
    if metadata.is_dir() {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            copy_path_recursive(&path, &dst.join(name))?;
        }
    } else {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(src, dst)?;
    }
    Ok(())
}

fn blob_path(runtime_dir: &Path, digest: &str) -> PathBuf {
    runtime_dir
        .join("images")
        .join("blobs")
        .join(digest.replace(':', "_"))
}

#[cfg(test)]
mod tests {
    use super::{build_from_dockerfile_with_store_and_compression, load_build_cache};
    use crate::image_fetch::resolve_layer_paths_with_store;
    use crate::image_store::LocalImageStore;
    use crate::layer_compression::CompressionFormat;
    use std::fs;

    #[test]
    fn builds_minimal_dockerfile() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\nCOPY . /\n").expect("write");
        fs::write(temp.path().join("hello.txt"), "hi").expect("write file");

        let runtime_dir = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime_dir.join("images")).expect("open store");
        let result = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/test:latest"),
            &runtime_dir,
            CompressionFormat::Gzip,
            &store,
        )
            .expect("build");
        let layers =
            resolve_layer_paths_with_store(&runtime_dir, &result.reference, &store).expect("layers");
        assert_eq!(layers.len(), 1);
        assert!(layers[0].exists());
    }

    #[test]
    fn stores_build_cache_entry() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\nCOPY . /\n").expect("write");
        fs::write(temp.path().join("hello.txt"), "hi").expect("write file");

        let runtime_dir = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime_dir.join("images")).expect("open store");
        let _ = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/test:latest"),
            &runtime_dir,
            CompressionFormat::Gzip,
            &store,
        )
        .expect("build");

        let cache = load_build_cache(&runtime_dir).expect("load cache");
        assert_eq!(cache.len(), 1);
    }
}
