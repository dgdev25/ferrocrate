#[cfg(target_os = "linux")]
use crate::capabilities::drop_all_capabilities;
use crate::image_fetch::{pull_image_with_store, resolve_layer_paths_with_store};
use crate::image_manifest::parse_image_manifest;
use crate::image_manifest::{
    Descriptor, ImageManifest, OCI_IMAGE_CONFIG_MEDIA_TYPE, OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE,
    OCI_IMAGE_LAYER_ZSTD_MEDIA_TYPE, OCI_IMAGE_MANIFEST_MEDIA_TYPE,
};
use crate::image_store::LocalImageStore;
use crate::image_tagging::{canonicalize_reference, resolve_reference};
use crate::layer_compression::{
    compress_bytes_gzip, compress_bytes_zstd, CompressionFormat, LayerCompressionError,
};
#[cfg(target_os = "linux")]
use crate::rootfs::{apply_layer_tar, construct_rootfs_with_dedup};
#[cfg(target_os = "linux")]
use crate::seccomp::{apply_seccomp_profile, default_seccomp_profile, SeccompProfile};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tar::Builder;
use thiserror::Error;

/// Maximum layer size (1GB) to prevent memory exhaustion attacks
const MAX_LAYER_SIZE: usize = 1024 * 1024 * 1024;

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
    #[error("layer size exceeds maximum ({0} bytes)")]
    LayerTooLarge(usize),
    #[error("image build authorization binding failed: {0}")]
    Authorization(String),
}

#[derive(Clone, Debug)]
pub struct ImageBuildPlan {
    dockerfile_path: PathBuf,
    runtime_dir: PathBuf,
    canonical_tag: String,
    compression: CompressionFormat,
    context_digest: String,
    dockerfile_digest: [u8; 32],
    base_digests: Vec<(String, Option<String>)>,
    plan_digest: [u8; 32],
}

impl ImageBuildPlan {
    pub fn canonical_tag(&self) -> &str {
        &self.canonical_tag
    }
    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }
    pub fn generation(&self) -> u64 {
        1
    }
}

pub fn prepare_dockerfile_build(
    dockerfile_path: &Path,
    tag: Option<&str>,
    runtime_dir: &Path,
    compression: CompressionFormat,
    store: &LocalImageStore,
) -> Result<ImageBuildPlan, DockerfileBuildError> {
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
    let context_digest = hash_context_dir(context_dir, dockerfile_path)?;
    let canonical_tag = canonicalize_reference(tag.unwrap_or("local/build:latest"))?;
    let mut base_digests = Vec::with_capacity(stages.len());
    for stage in stages {
        if stage.base.eq_ignore_ascii_case("scratch") {
            base_digests.push((stage.base, None));
        } else {
            let record = resolve_reference(store, &stage.base)?.ok_or_else(|| {
                DockerfileBuildError::Invalid(format!("base image not found: {}", stage.base))
            })?;
            base_digests.push((stage.base, Some(record.digest)));
        }
    }
    let dockerfile_digest: [u8; 32] = Sha256::digest(dockerfile.as_bytes()).into();
    let mut hash = Sha256::new();
    hash.update(b"ferrocrate/image-build-plan/v1");
    for value in [canonical_tag.as_str(), context_digest.as_str()] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.update(dockerfile_digest);
    hash.update([match compression {
        CompressionFormat::None => 0,
        CompressionFormat::Gzip => 1,
        CompressionFormat::Zstd => 2,
    }]);
    hash.update((base_digests.len() as u64).to_be_bytes());
    for (reference, digest) in &base_digests {
        hash.update((reference.len() as u64).to_be_bytes());
        hash.update(reference.as_bytes());
        let digest = digest.as_deref().unwrap_or("");
        hash.update((digest.len() as u64).to_be_bytes());
        hash.update(digest.as_bytes());
    }
    Ok(ImageBuildPlan {
        dockerfile_path: dockerfile_path.to_path_buf(),
        runtime_dir: runtime_dir.to_path_buf(),
        canonical_tag,
        compression,
        context_digest,
        dockerfile_digest,
        base_digests,
        plan_digest: hash.finalize().into(),
    })
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
    #[serde(default)]
    cache_key: String,
    #[serde(default)]
    created_at_unix: u64,
    #[serde(default)]
    context_digest: String,
    #[serde(default)]
    dockerfile_digest: String,
    #[serde(default)]
    base_digests: Vec<String>,
    layer_digest: String,
    layer_size: i64,
    layer_media_type: String,
    config_digest: String,
    config_json: String,
    manifest_json: String,
}

#[allow(dead_code)]
fn build_from_dockerfile(
    dockerfile_path: &Path,
    tag: Option<&str>,
    runtime_dir: &Path,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
) -> Result<BuildResult, DockerfileBuildError> {
    build_from_dockerfile_with_compression(
        dockerfile_path,
        tag,
        runtime_dir,
        CompressionFormat::Gzip,
        authority,
    )
}

#[allow(dead_code)]
pub(crate) fn build_from_dockerfile_with_compression(
    dockerfile_path: &Path,
    tag: Option<&str>,
    runtime_dir: &Path,
    compression: CompressionFormat,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
) -> Result<BuildResult, DockerfileBuildError> {
    let store = LocalImageStore::open(runtime_dir.join("images"))?;
    build_from_dockerfile_with_store_and_compression(
        dockerfile_path,
        tag,
        runtime_dir,
        compression,
        &store,
        authority,
    )
}

pub(crate) fn build_from_dockerfile_with_store_and_compression(
    dockerfile_path: &Path,
    tag: Option<&str>,
    runtime_dir: &Path,
    compression: CompressionFormat,
    store: &LocalImageStore,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
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
    let dockerfile_digest = hex::encode(Sha256::digest(dockerfile.as_bytes()));
    let mut base_infos = Vec::new();
    for stage in stages.iter() {
        let base_info = resolve_base_image(store, runtime_dir, &stage.base, authority)?;
        base_infos.push(base_info);
    }
    let cache_key = build_cache_key(&dockerfile, compression, &context_hash, &base_infos);
    let base_digests = base_infos
        .iter()
        .map(|info| info.digest.clone().unwrap_or_else(|| "scratch".to_string()))
        .collect::<Vec<_>>();
    let mut cache = load_build_cache(runtime_dir)?;
    if let Some(entry) = cache.get(&cache_key).cloned() {
        if !entry.cache_key.is_empty() && entry.cache_key != cache_key {
            return Err(DockerfileBuildError::Invalid(
                "build cache provenance key mismatch".to_string(),
            ));
        }
        if (!entry.context_digest.is_empty() && entry.context_digest != context_hash)
            || (!entry.dockerfile_digest.is_empty() && entry.dockerfile_digest != dockerfile_digest)
            || (!entry.base_digests.is_empty() && entry.base_digests != base_digests)
        {
            return Err(DockerfileBuildError::Invalid(
                "build cache source provenance mismatch".to_string(),
            ));
        }
        let layer_path = layer_blob_path(runtime_dir, &entry.layer_digest);
        let config_path = config_path(runtime_dir, &entry.config_digest);
        if layer_path.exists() && config_path.exists() {
            let reference = canonicalize_reference(tag.unwrap_or("local/build:latest"))?;
            store.put_reference(
                authority,
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
    let ignore_patterns = load_dockerignore_patterns(context_dir)?;

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
        if stage.copy_paths.is_empty() {
            copy_context_dir(
                context_dir,
                context_dir,
                &context_root,
                dockerfile_path,
                &ignore_patterns,
            )?;
        } else {
            copy_from_context(context_dir, &context_root, &stage.copy_paths)?;
        }

        for copy in &stage.copy_from {
            let source_root = resolve_stage_root(&stage_roots, &stage_names, &copy.from)
                .ok_or_else(|| {
                    DockerfileBuildError::Invalid(format!(
                        "unknown COPY --from stage: {}",
                        copy.from
                    ))
                })?;
            let source = source_root.join(copy.src.trim_start_matches('/'));
            let dest = context_root.join(copy.dest.trim_start_matches('/'));
            copy_path_recursive(&source, &dest)?;
        }

        let (mut layer_bytes, mut layer_media_type) =
            build_layer_from_dir(&context_root, Some(dockerfile_path), compression)?;
        let mut layer_digest = sha256_digest_bytes(&layer_bytes);
        let mut layer_size = layer_bytes.len() as i64;
        write_blob(runtime_dir, &layer_digest, &layer_bytes)?;

        let layer_path = layer_blob_path(runtime_dir, &layer_digest);
        apply_layer_tar(&stage_root, &layer_path)
            .map_err(|err| DockerfileBuildError::Invalid(err.to_string()))?;

        if !stage.run.is_empty() {
            apply_stage_workdir(&stage_root, stage.workdir.as_deref())?;
            run_stage_commands(
                &stage_root,
                &stage.run,
                &stage.env,
                stage.workdir.as_deref(),
                stage.user.as_deref(),
                &runtime_dir.join("build").join("cache"),
            )?;
            let (rebuilt, media_type) = build_layer_from_dir(&stage_root, None, compression)?;
            layer_bytes = rebuilt;
            layer_media_type = media_type;
            layer_digest = sha256_digest_bytes(&layer_bytes);
            layer_size = layer_bytes.len() as i64;
            write_blob(runtime_dir, &layer_digest, &layer_bytes)?;
        }

        stage_roots.push(stage_root.clone());
        if let Some(name) = stage.name.as_ref() {
            stage_names.insert(name.to_string(), stage_root.clone());
        }

        if idx == stages.len() - 1 {
            let config_json = build_config_json(
                stage.healthcheck.clone(),
                &stage.env,
                &stage.labels,
                stage.workdir.as_deref(),
                stage.user.as_deref(),
                stage.entrypoint.clone(),
                stage.cmd.clone(),
                &stage.exposed_ports,
                &stage.volumes,
            );
            let config_bytes = config_json.as_bytes();
            let config_digest = sha256_digest_bytes(config_bytes);

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
            let manifest_json = serde_json::to_string(&manifest)
                .map_err(|err| io::Error::other(err.to_string()))?;

            let reference = canonicalize_reference(tag.unwrap_or("local/build:latest"))?;
            store.put_reference(
                authority,
                &reference,
                &config_digest,
                OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                &manifest_json,
            )?;

            write_config(runtime_dir, &config_digest, config_bytes)?;

            cache.insert(
                cache_key.clone(),
                BuildCacheEntry {
                    cache_key: cache_key.clone(),
                    created_at_unix: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    context_digest: context_hash.clone(),
                    dockerfile_digest: dockerfile_digest.clone(),
                    base_digests: base_digests.clone(),
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

pub fn execute_dockerfile_build_authorized(
    plan: ImageBuildPlan,
    store: &LocalImageStore,
    permit: crate::authorization::surface::SurfacePermit,
) -> Result<BuildResult, DockerfileBuildError> {
    crate::authorization::surface::SurfaceAuthorization::validate_execution(
        &permit,
        crate::authorization::Action::ImageBuild,
        crate::authorization::ResourceKind::Image,
        plan.canonical_tag(),
        plan.generation(),
    )
    .map_err(|error| DockerfileBuildError::Authorization(error.to_string()))?;
    if permit.proof().canonical().operation_plan_digest() != Some(&plan.plan_digest()) {
        permit
            .finish(false)
            .map_err(|error| DockerfileBuildError::Authorization(error.to_string()))?;
        return Err(DockerfileBuildError::Authorization(
            "image build plan does not match authorization proof".to_string(),
        ));
    }
    let observed = prepare_dockerfile_build(
        &plan.dockerfile_path,
        Some(&plan.canonical_tag),
        &plan.runtime_dir,
        plan.compression,
        store,
    )?;
    if observed.plan_digest != plan.plan_digest
        || observed.context_digest != plan.context_digest
        || observed.dockerfile_digest != plan.dockerfile_digest
        || observed.base_digests != plan.base_digests
    {
        permit
            .finish(false)
            .map_err(|error| DockerfileBuildError::Authorization(error.to_string()))?;
        return Err(DockerfileBuildError::Authorization(
            "image build inputs changed after authorization".to_string(),
        ));
    }
    let authority = permit.mutation_authority();
    match build_from_dockerfile_with_store_and_compression(
        &plan.dockerfile_path,
        Some(&plan.canonical_tag),
        &plan.runtime_dir,
        plan.compression,
        store,
        &authority,
    ) {
        Ok(result) => {
            permit
                .finish(true)
                .map_err(|error| DockerfileBuildError::Authorization(error.to_string()))?;
            Ok(result)
        }
        Err(error) => {
            permit
                .finish_unknown()
                .map_err(|finish| DockerfileBuildError::Authorization(finish.to_string()))?;
            Err(error)
        }
    }
}

fn build_layer_from_dir(
    source_dir: &Path,
    dockerfile_path: Option<&Path>,
    compression: CompressionFormat,
) -> Result<(Vec<u8>, String), DockerfileBuildError> {
    let mut tar_builder = Builder::new(Vec::new());
    add_directory(&mut tar_builder, source_dir, source_dir, dockerfile_path)?;
    let tar_bytes = tar_builder
        .into_inner()
        .map_err(|err| io::Error::other(err.to_string()))?;

    // Security: Check layer size to prevent memory exhaustion
    if tar_bytes.len() > MAX_LAYER_SIZE {
        return Err(DockerfileBuildError::LayerTooLarge(tar_bytes.len()));
    }

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
                .map_err(DockerfileBuildError::Io)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_config_json(
    healthcheck: Option<HealthcheckSpec>,
    env: &[String],
    labels: &HashMap<String, String>,
    workdir: Option<&str>,
    user: Option<&str>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    exposed_ports: &[String],
    volumes: &[String],
) -> String {
    let health = healthcheck.map(|spec| {
        json!({
            "Test": spec.test,
            "Interval": spec.interval_nanos,
            "Timeout": spec.timeout_nanos,
            "Retries": spec.retries,
            "StartPeriod": spec.start_period_nanos
        })
    });

    let exposed = if exposed_ports.is_empty() {
        None
    } else {
        let map = exposed_ports
            .iter()
            .map(|port| (port.clone(), serde_json::Value::Object(Default::default())))
            .collect::<serde_json::Map<_, _>>();
        Some(serde_json::Value::Object(map))
    };
    let volumes = if volumes.is_empty() {
        None
    } else {
        let map = volumes
            .iter()
            .map(|path| (path.clone(), serde_json::Value::Object(Default::default())))
            .collect::<serde_json::Map<_, _>>();
        Some(serde_json::Value::Object(map))
    };

    json!({
        "created": "1970-01-01T00:00:00Z",
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Env": env,
            "Cmd": cmd,
            "Entrypoint": entrypoint,
            "WorkingDir": workdir,
            "User": user,
            "Labels": labels,
            "Healthcheck": health,
            "ExposedPorts": exposed,
            "Volumes": volumes
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
    let cas_root = runtime_dir.join("images").join("cas").join("shake256");
    fs::create_dir_all(&cas_root)?;
    let hash = hex::encode(rvf_crypto::shake256_256(bytes));
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
        .map_err(|err| io::Error::other(err.to_string()))?;
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
    let bytes = serde_json::to_vec(cache).map_err(|err| io::Error::other(err.to_string()))?;
    let temporary = path.with_extension(format!("json.tmp.{}", std::process::id()));
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    Ok(())
}

/// Export validated local cache metadata to a caller-selected file.
pub fn export_build_cache(
    runtime_dir: &Path,
    destination: &Path,
) -> Result<(), DockerfileBuildError> {
    let cache = load_build_cache(runtime_dir)?;
    let bytes =
        serde_json::to_vec_pretty(&cache).map_err(|error| io::Error::other(error.to_string()))?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = destination.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, destination)?;
    Ok(())
}

/// Import cache metadata, merging entries into the local cache. Malformed
/// metadata fails closed and no partial write is published.
pub fn import_build_cache(
    runtime_dir: &Path,
    source: &Path,
) -> Result<usize, DockerfileBuildError> {
    let bytes = fs::read(source)?;
    let imported = serde_json::from_slice::<HashMap<String, BuildCacheEntry>>(&bytes)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut cache = load_build_cache(runtime_dir)?;
    let count = imported.len();
    cache.extend(imported);
    save_build_cache(runtime_dir, &cache)?;
    Ok(count)
}

/// Retain the newest `max_entries` local build-cache records. Entries are
/// ordered by their persisted provenance timestamp and the update is atomic.
pub fn prune_build_cache(
    runtime_dir: &Path,
    max_entries: usize,
) -> Result<usize, DockerfileBuildError> {
    let mut cache = load_build_cache(runtime_dir)?;
    if cache.len() <= max_entries {
        return Ok(0);
    }
    let mut entries = cache
        .iter()
        .map(|(key, entry)| (key.clone(), entry.created_at_unix))
        .collect::<Vec<_>>();
    entries.sort_by_key(|(_, created_at)| *created_at);
    let remove_count = entries.len() - max_entries;
    for (key, _) in entries.into_iter().take(remove_count) {
        cache.remove(&key);
    }
    save_build_cache(runtime_dir, &cache)?;
    Ok(remove_count)
}

fn build_cache_key(
    dockerfile: &str,
    compression: CompressionFormat,
    context_hash: &str,
    base_infos: &[BaseImageInfo],
) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(dockerfile.as_bytes());
    buf.extend_from_slice(context_hash.as_bytes());
    buf.extend_from_slice(format!("{compression:?}").as_bytes());
    for info in base_infos {
        if let Some(digest) = &info.digest {
            buf.extend_from_slice(digest.as_bytes());
        }
    }
    hex::encode(rvf_crypto::shake256_256(&buf))
}

fn hash_context_dir(
    context_dir: &Path,
    dockerfile_path: &Path,
) -> Result<String, DockerfileBuildError> {
    let ignore_patterns = load_dockerignore_patterns(context_dir)?;
    let mut files = Vec::new();
    collect_context_files(
        context_dir,
        context_dir,
        dockerfile_path,
        &ignore_patterns,
        &mut files,
    )?;
    files.sort();
    let mut buf = Vec::new();
    for rel_path in files {
        let full_path = context_dir.join(&rel_path);
        buf.extend_from_slice(rel_path.to_string_lossy().as_bytes());
        let bytes = fs::read(&full_path)?;
        buf.extend_from_slice(&bytes);
    }
    Ok(hex::encode(rvf_crypto::shake256_256(&buf)))
}

fn collect_context_files(
    base: &Path,
    path: &Path,
    dockerfile_path: &Path,
    ignore_patterns: &[String],
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
        if should_ignore_context_path(&relative, ignore_patterns) {
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
            collect_context_files(base, &entry_path, dockerfile_path, ignore_patterns, out)?;
        } else if file_type.is_file() {
            out.push(relative);
        }
    }
    Ok(())
}

fn load_dockerignore_patterns(context_dir: &Path) -> Result<Vec<String>, DockerfileBuildError> {
    let path = context_dir.join(".dockerignore");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('!'))
        .map(ToOwned::to_owned)
        .collect())
}

fn should_ignore_context_path(relative: &Path, patterns: &[String]) -> bool {
    let path = relative.to_string_lossy();
    patterns
        .iter()
        .any(|pattern| dockerignore_matches(pattern, &path))
}

fn dockerignore_matches(pattern: &str, path: &str) -> bool {
    let normalized = pattern.trim_start_matches("./");
    if normalized.is_empty() {
        return false;
    }
    if let Some(prefix) = normalized.strip_suffix('/') {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if normalized.contains('*') {
        return wildcard_match(normalized, path);
    }
    path == normalized || path.starts_with(&format!("{normalized}/"))
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let mut remainder = value;
    let mut first = true;
    for part in pattern.split('*').filter(|part| !part.is_empty()) {
        if first {
            if !pattern.starts_with('*') {
                if !remainder.starts_with(part) {
                    return false;
                }
                remainder = &remainder[part.len()..];
            } else if let Some(pos) = remainder.find(part) {
                remainder = &remainder[pos + part.len()..];
            } else {
                return false;
            }
            first = false;
            continue;
        }
        if let Some(pos) = remainder.find(part) {
            remainder = &remainder[pos + part.len()..];
        } else {
            return false;
        }
    }
    if pattern.ends_with('*') {
        true
    } else {
        pattern
            .split('*')
            .next_back()
            .map(|tail| tail.is_empty() || value.ends_with(tail))
            .unwrap_or(false)
    }
}

fn config_path(runtime_dir: &Path, digest: &str) -> PathBuf {
    runtime_dir
        .join("images")
        .join("configs")
        .join(digest.replace(':', "_"))
}

fn sha256_digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

#[derive(Debug, Clone)]
struct CopyFromSpec {
    from: String,
    src: String,
    dest: String,
}

#[derive(Debug, Clone)]
struct CopySpec {
    srcs: Vec<String>,
    dest: String,
    chmod: Option<u32>,
}

#[derive(Debug, Clone)]
struct StageSpec {
    base: String,
    name: Option<String>,
    copy_from: Vec<CopyFromSpec>,
    copy_paths: Vec<CopySpec>,
    healthcheck: Option<HealthcheckSpec>,
    env: Vec<String>,
    args: HashMap<String, String>,
    labels: HashMap<String, String>,
    workdir: Option<String>,
    user: Option<String>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    shell: Vec<String>,
    run: Vec<RunSpec>,
    exposed_ports: Vec<String>,
    volumes: Vec<String>,
}

fn parse_stages(contents: &str) -> Result<Vec<StageSpec>, DockerfileBuildError> {
    let mut stages = Vec::new();
    let mut current: Option<StageSpec> = None;
    let mut global_args: HashMap<String, String> = HashMap::new();

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
            let resolved_from = interpolate_value(&value, &[], &global_args);
            let (base, name) = parse_from(&resolved_from)?;
            current = Some(StageSpec {
                base,
                name,
                copy_from: Vec::new(),
                copy_paths: Vec::new(),
                healthcheck: None,
                env: Vec::new(),
                args: global_args.clone(),
                labels: HashMap::new(),
                workdir: None,
                user: None,
                entrypoint: None,
                cmd: None,
                shell: vec!["/bin/sh".to_string(), "-c".to_string()],
                run: Vec::new(),
                exposed_ports: Vec::new(),
                volumes: Vec::new(),
            });
            continue;
        }

        if current.is_none() && keyword == "ARG" {
            let (name, value) = parse_arg(&value)?;
            global_args.insert(name, value);
            continue;
        }

        let stage = current
            .as_mut()
            .ok_or_else(|| DockerfileBuildError::Invalid("missing FROM instruction".to_string()))?;
        let interpolated = interpolate_value(&value, &stage.env, &stage.args);

        match keyword.as_str() {
            "COPY" => {
                if let Some(copy) = parse_copy_from(&interpolated)? {
                    stage.copy_from.push(copy);
                } else if let Some(copy) = parse_copy_spec(&interpolated)? {
                    stage.copy_paths.push(copy);
                }
            }
            "ADD" => {
                if let Some(copy) = parse_copy_spec(&interpolated)? {
                    stage.copy_paths.push(copy);
                }
            }
            "RUN" => {
                let run = parse_run(&interpolated, &stage.shell)?;
                stage.run.push(run);
            }
            "ARG" => {
                let (name, value) = parse_arg(&interpolated)?;
                stage.args.insert(name.clone(), value);
            }
            "ENV" => {
                let env = parse_env(&interpolated)?;
                stage.env.extend(env);
            }
            "LABEL" => {
                let labels = parse_labels(&interpolated)?;
                stage.labels.extend(labels);
            }
            "WORKDIR" => {
                stage.workdir = Some(interpolated.to_string());
            }
            "USER" => {
                stage.user = Some(interpolated.to_string());
            }
            "EXPOSE" => {
                stage
                    .exposed_ports
                    .extend(interpolated.split_whitespace().map(|val| val.to_string()));
            }
            "VOLUME" => {
                stage.volumes.extend(parse_volume_paths(&interpolated)?);
            }
            "ENTRYPOINT" => {
                stage.entrypoint = Some(parse_exec_or_shell(&interpolated, &stage.shell)?);
            }
            "CMD" => {
                stage.cmd = Some(parse_exec_or_shell(&interpolated, &stage.shell)?);
            }
            "HEALTHCHECK" => {
                stage.healthcheck = parse_healthcheck(&interpolated)?;
            }
            "SHELL" => {
                stage.shell = parse_json_array(&interpolated)?;
                if stage.shell.is_empty() {
                    return Err(DockerfileBuildError::Invalid(
                        "SHELL requires at least one argument".to_string(),
                    ));
                }
            }
            "STOPSIGNAL" | "MAINTAINER" | "ONBUILD" => {
                return Err(DockerfileBuildError::Unsupported(format!(
                    "instruction {keyword} is not supported"
                )));
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

fn parse_copy_spec(value: &str) -> Result<Option<CopySpec>, DockerfileBuildError> {
    let tokens = value.split_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        return Ok(None);
    }
    let mut args = Vec::new();
    let mut chmod = None;
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        if let Some(raw_mode) = token.strip_prefix("--chmod=") {
            chmod = Some(parse_copy_mode(raw_mode)?);
        } else if token == "--chmod" {
            let raw_mode = tokens.get(index + 1).ok_or_else(|| {
                DockerfileBuildError::Invalid("COPY --chmod requires a mode".to_string())
            })?;
            chmod = Some(parse_copy_mode(raw_mode)?);
            index += 1;
        } else if token.starts_with("--") {
            return Err(DockerfileBuildError::Unsupported(format!(
                "COPY flag {token} is not supported"
            )));
        } else {
            args.push(token);
        }
        index += 1;
    }
    if args.len() < 2 {
        return Err(DockerfileBuildError::Invalid(
            "COPY/ADD requires src and dest".to_string(),
        ));
    }
    // CQ-01: Use checked index access instead of unwrap()
    let dest = args
        .last()
        .ok_or_else(|| DockerfileBuildError::Invalid("COPY dest missing".to_string()))?
        .to_string();
    let srcs = args[..args.len() - 1]
        .iter()
        .map(|s| s.to_string())
        .collect();
    Ok(Some(CopySpec { srcs, dest, chmod }))
}

fn parse_copy_mode(raw: &str) -> Result<u32, DockerfileBuildError> {
    if raw.is_empty() || raw.len() > 4 || !raw.bytes().all(|byte| (b'0'..=b'7').contains(&byte)) {
        return Err(DockerfileBuildError::Invalid(format!(
            "invalid COPY --chmod mode: {raw}"
        )));
    }
    u32::from_str_radix(raw, 8)
        .map_err(|_| DockerfileBuildError::Invalid(format!("invalid COPY --chmod mode: {raw}")))
}

fn parse_arg(value: &str) -> Result<(String, String), DockerfileBuildError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(DockerfileBuildError::Invalid(
            "ARG requires a name".to_string(),
        ));
    }
    let part = trimmed.split_whitespace().next().unwrap_or(trimmed);
    if let Some((key, val)) = part.split_once('=') {
        return Ok((key.to_string(), val.to_string()));
    }
    Ok((part.to_string(), std::env::var(part).unwrap_or_default()))
}

fn parse_volume_paths(value: &str) -> Result<Vec<String>, DockerfileBuildError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') {
        return parse_json_array(trimmed);
    }
    Ok(trimmed.split_whitespace().map(|s| s.to_string()).collect())
}

fn interpolate_value(value: &str, env: &[String], args: &HashMap<String, String>) -> String {
    let mut map = HashMap::new();
    for entry in env {
        if let Some((key, val)) = entry.split_once('=') {
            map.insert(key.to_string(), val.to_string());
        }
    }
    for (key, val) in args {
        map.entry(key.to_string())
            .or_insert_with(|| val.to_string());
    }
    let mut out = String::new();
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' {
            if let Some('{') = chars.peek().copied() {
                chars.next();
                let mut var = String::new();
                for next in chars.by_ref() {
                    if next == '}' {
                        break;
                    }
                    var.push(next);
                }
                if let Some(val) = map.get(&var) {
                    out.push_str(val);
                }
                continue;
            }
            let mut var = String::new();
            while let Some(next) = chars.peek().copied() {
                if next.is_ascii_alphanumeric() || next == '_' {
                    var.push(next);
                    chars.next();
                } else {
                    break;
                }
            }
            if !var.is_empty() {
                if let Some(val) = map.get(&var) {
                    out.push_str(val);
                }
                continue;
            }
        }
        out.push(ch);
    }
    out
}

#[derive(Debug, Clone)]
struct HealthcheckSpec {
    test: Vec<String>,
    interval_nanos: u64,
    timeout_nanos: u64,
    retries: u32,
    start_period_nanos: u64,
}

#[derive(Debug, Clone)]
struct RunSpec {
    args: Vec<String>,
    _shell: bool,
    cache_mounts: Vec<CacheMount>,
}

#[derive(Debug, Clone)]
struct CacheMount {
    target: String,
    id: String,
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

fn parse_run(raw: &str, shell: &[String]) -> Result<RunSpec, DockerfileBuildError> {
    let trimmed = raw.trim();
    let mut tokens = trimmed.split_whitespace().collect::<Vec<_>>();
    let mut cache_mounts = Vec::new();
    while tokens
        .first()
        .is_some_and(|token| token.starts_with("--mount="))
    {
        let mount = tokens.remove(0).trim_start_matches("--mount=");
        let mut kind = None;
        let mut target = None;
        let mut id = None;
        for option in mount.split(',') {
            let (key, value) = option.split_once('=').unwrap_or((option, ""));
            match key {
                "type" => kind = Some(value),
                "target" | "dst" | "destination" => target = Some(value),
                "id" => id = Some(value),
                "ro" | "readonly" | "sharing" => {}
                _ => {
                    return Err(DockerfileBuildError::Unsupported(format!(
                        "RUN --mount option is not supported: {key}"
                    )))
                }
            }
        }
        match kind {
            Some("cache") => {
                let target = target.ok_or_else(|| {
                    DockerfileBuildError::Invalid("cache mount requires target".to_string())
                })?;
                let target = validate_cache_target(target)?;
                let id = id.unwrap_or(target.trim_start_matches('/'));
                let id = validate_cache_id(id)?;
                cache_mounts.push(CacheMount { target, id });
            }
            Some("secret") | Some("ssh") => {
                return Err(DockerfileBuildError::Unsupported(format!(
                    "RUN --mount=type={} is not supported",
                    kind.unwrap()
                )))
            }
            Some(other) => {
                return Err(DockerfileBuildError::Unsupported(format!(
                    "RUN --mount=type={other} is not supported"
                )))
            }
            None => {
                return Err(DockerfileBuildError::Invalid(
                    "RUN mount requires type".to_string(),
                ))
            }
        }
    }
    let command = tokens.join(" ");
    if command.starts_with('[') {
        if !cache_mounts.is_empty() {
            return Err(DockerfileBuildError::Unsupported(
                "cache mounts require shell-form RUN".to_string(),
            ));
        }
        let args = parse_json_array(&command)?;
        return Ok(RunSpec {
            args,
            _shell: false,
            cache_mounts,
        });
    }
    if shell.is_empty() {
        return Err(DockerfileBuildError::Invalid(
            "SHELL requires at least one argument".to_string(),
        ));
    }
    let mut args = shell.to_vec();
    args.push(command);
    Ok(RunSpec {
        args,
        _shell: true,
        cache_mounts,
    })
}

fn validate_cache_target(target: &str) -> Result<String, DockerfileBuildError> {
    let path = Path::new(target);
    if !path.is_absolute() || target == "/" || target.contains("..") {
        return Err(DockerfileBuildError::Invalid(
            "cache mount target must be an absolute non-parent path".to_string(),
        ));
    }
    Ok(target.trim_end_matches('/').to_string())
}

fn validate_cache_id(id: &str) -> Result<String, DockerfileBuildError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(DockerfileBuildError::Invalid(
            "cache mount id contains invalid characters".to_string(),
        ));
    }
    Ok(id.to_string())
}

fn parse_env(raw: &str) -> Result<Vec<String>, DockerfileBuildError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.contains('=') {
        return Ok(trimmed
            .split_whitespace()
            .filter(|entry| !entry.trim().is_empty())
            .map(|entry| entry.to_string())
            .collect());
    }

    let tokens = trimmed.split_whitespace().collect::<Vec<_>>();
    if tokens.len() < 2 {
        return Err(DockerfileBuildError::Invalid(
            "ENV requires key and value".to_string(),
        ));
    }
    let key = tokens[0];
    let value = tokens[1..].join(" ");
    Ok(vec![format!("{key}={value}")])
}

fn parse_labels(raw: &str) -> Result<HashMap<String, String>, DockerfileBuildError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(HashMap::new());
    }
    let mut out = HashMap::new();
    let tokens = trimmed.split_whitespace().collect::<Vec<_>>();
    for token in tokens {
        if let Some((key, value)) = token.split_once('=') {
            let value = value.trim_matches('"').trim_matches('\'');
            out.insert(key.to_string(), value.to_string());
        } else {
            return Err(DockerfileBuildError::Invalid(
                "LABEL requires key=value".to_string(),
            ));
        }
    }
    Ok(out)
}

fn parse_exec_or_shell(raw: &str, shell: &[String]) -> Result<Vec<String>, DockerfileBuildError> {
    let trimmed = raw.trim();
    if trimmed.starts_with('[') {
        return parse_json_array(trimmed);
    }
    if shell.is_empty() {
        return Err(DockerfileBuildError::Invalid(
            "SHELL requires at least one argument".to_string(),
        ));
    }
    let mut args = shell.to_vec();
    args.push(trimmed.to_string());
    Ok(args)
}

fn parse_json_array(raw: &str) -> Result<Vec<String>, DockerfileBuildError> {
    let parsed: Vec<String> = serde_json::from_str(raw)
        .map_err(|err| DockerfileBuildError::Invalid(format!("invalid JSON array: {err}")))?;
    Ok(parsed)
}

fn apply_stage_workdir(rootfs: &Path, workdir: Option<&str>) -> Result<(), DockerfileBuildError> {
    let Some(workdir) = workdir else {
        return Ok(());
    };
    let path = workdir.trim();
    if path.is_empty() {
        return Ok(());
    }
    let target = if path.starts_with('/') {
        rootfs.join(path.trim_start_matches('/'))
    } else {
        rootfs.join(path)
    };
    fs::create_dir_all(&target)?;
    Ok(())
}

fn run_stage_commands(
    rootfs: &Path,
    runs: &[RunSpec],
    env: &[String],
    workdir: Option<&str>,
    user: Option<&str>,
    cache_root: &Path,
) -> Result<(), DockerfileBuildError> {
    let seccomp_profile = load_build_seccomp_profile()?;
    let build_limits = load_build_limits()?;
    let running_as_root = nix::unistd::Uid::effective().is_root();
    fs::create_dir_all(cache_root)?;
    for run in runs {
        if run.args.is_empty() {
            return Err(DockerfileBuildError::Invalid(
                "RUN instruction produced empty command".to_string(),
            ));
        }
        let mut cmd = Command::new(&run.args[0]);
        cmd.args(&run.args[1..]);
        cmd.stdin(Stdio::null());

        // Set environment variables
        for entry in env {
            let mut parts = entry.splitn(2, '=');
            let key = parts.next().unwrap_or("").trim();
            let value = parts.next().unwrap_or("").trim();
            if !key.is_empty() {
                cmd.env(key, value);
            }
        }

        let rootfs = rootfs.to_path_buf();
        let command_rootfs = rootfs.clone();
        let workdir = workdir.map(|v| v.to_string());
        let run_user = user.map(|v| v.to_string());
        let seccomp = seccomp_profile.clone();
        let limits = build_limits.clone();
        let child_limits = limits.clone();
        // SAFETY: pre_exec runs in the child process between fork and exec to install
        // sandboxing primitives that must be process-local (namespaces/seccomp/chroot).
        unsafe {
            cmd.pre_exec(move || {
                if running_as_root {
                    setup_build_namespace_root().map_err(|err| {
                        io::Error::new(
                            err.kind(),
                            format!("build pre_exec unshare root namespaces: {err}"),
                        )
                    })?;
                } else {
                    setup_build_namespace().map_err(|err| {
                        io::Error::new(
                            err.kind(),
                            format!("build pre_exec unshare namespaces: {err}"),
                        )
                    })?;
                    apply_user_namespace_map().map_err(|err| {
                        io::Error::new(
                            err.kind(),
                            format!("build pre_exec map user namespace: {err}"),
                        )
                    })?;
                }
                enter_build_rootfs(&command_rootfs, workdir.as_deref()).map_err(|err| {
                    io::Error::new(err.kind(), format!("build pre_exec enter rootfs: {err}"))
                })?;
                apply_build_identity(run_user.as_deref()).map_err(|err| {
                    io::Error::new(err.kind(), format!("build pre_exec set identity: {err}"))
                })?;
                if let Err(err) = set_no_new_privileges() {
                    if err.raw_os_error() == Some(nix::libc::EINVAL)
                        || err.raw_os_error() == Some(nix::libc::EPERM)
                    {
                        log::warn!("build pre_exec ignoring no_new_privs error: {err}");
                    } else {
                        return Err(io::Error::new(
                            err.kind(),
                            format!("build pre_exec set no_new_privs: {err}"),
                        ));
                    }
                }
                drop_all_capabilities()
                    .map_err(|err| io::Error::other(format!("build pre_exec drop capabilities: {err}")))?;
                if let Some(profile) = &seccomp {
                    if let Err(err) = apply_seccomp_profile(profile) {
                        let err_text = err.to_string();
                        let invalid_arg = err_text.contains("Invalid argument")
                            || err_text.contains("invalid argument");
                        if invalid_arg {
                            log::warn!(
                                "build pre_exec seccomp apply failed, continuing without seccomp: {}",
                                err
                            );
                        } else {
                            return Err(io::Error::other(format!(
                                "build pre_exec apply seccomp: {err}"
                            )));
                        }
                    }
                }
                apply_build_limits(&child_limits).map_err(|err| {
                    io::Error::new(err.kind(), format!("build pre_exec apply limits: {err}"))
                })?;
                Ok(())
            });
        }

        let mut mounted = Vec::new();
        for (index, mount) in run.cache_mounts.iter().enumerate() {
            let target = rootfs.join(mount.target.trim_start_matches('/'));
            let backup = rootfs.join(format!(".ferrocrate-cache-backup-{index}"));
            let existed = target.exists();
            if existed {
                fs::rename(&target, &backup)?;
            }
            let cache = cache_root.join(&mount.id);
            fs::create_dir_all(&cache)?;
            fs::create_dir_all(&target)?;
            reject_cache_symlinks(&cache)?;
            copy_path_recursive(&cache, &target)?;
            mounted.push((target, backup, cache, existed));
        }
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                for (target, backup, _cache, existed) in mounted.iter().rev() {
                    let _ = fs::remove_dir_all(&target);
                    if *existed {
                        fs::rename(backup, target)?;
                    }
                }
                return Err(err.into());
            }
        };
        let started = Instant::now();
        let status_result = loop {
            if let Some(status) = child.try_wait()? {
                break Ok(status);
            }
            let cancelled = limits
                .cancel_file
                .as_ref()
                .is_some_and(|path| path.exists());
            let timed_out = limits
                .timeout
                .is_some_and(|timeout| started.elapsed() >= timeout);
            if cancelled || timed_out {
                let _ = child.kill();
                let _ = child.wait();
                let reason = if cancelled { "cancelled" } else { "timed out" };
                break Err(DockerfileBuildError::Invalid(format!(
                    "RUN {reason} by build control"
                )));
            }
            thread::sleep(Duration::from_millis(20));
        };
        let mut cleanup_error = None;
        for (target, backup, cache, existed) in mounted.into_iter().rev() {
            if target.exists() {
                if let Err(err) = reject_cache_symlinks(&target) {
                    cleanup_error.get_or_insert(err);
                } else if let Err(err) = copy_path_recursive(&target, &cache) {
                    cleanup_error.get_or_insert(err);
                }
                let _ = fs::remove_dir_all(&target);
            }
            if existed {
                fs::rename(backup, target)?;
            }
        }
        if let Some(err) = cleanup_error {
            return Err(err);
        }
        let status = status_result?;
        if !status.success() {
            return Err(DockerfileBuildError::Invalid(format!(
                "RUN failed with status {status}"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct BuildLimits {
    memory_bytes: Option<u64>,
    cpu_seconds: Option<u64>,
    timeout: Option<Duration>,
    cancel_file: Option<PathBuf>,
}

fn load_build_limits() -> Result<BuildLimits, DockerfileBuildError> {
    let memory_bytes = parse_limit_env("FERROCRATE_BUILD_MEMORY_MAX")?;
    let cpu_seconds = parse_limit_env("FERROCRATE_BUILD_CPU_SECONDS")?;
    let timeout = parse_limit_env("FERROCRATE_BUILD_TIMEOUT_MS")?.map(Duration::from_millis);
    let cancel_file = std::env::var_os("FERROCRATE_BUILD_CANCEL_FILE").map(PathBuf::from);
    if let Some(path) = &cancel_file {
        if !path.is_absolute() {
            return Err(DockerfileBuildError::Invalid(
                "FERROCRATE_BUILD_CANCEL_FILE must be absolute".to_string(),
            ));
        }
    }
    Ok(BuildLimits {
        memory_bytes,
        cpu_seconds,
        timeout,
        cancel_file,
    })
}

fn parse_limit_env(name: &str) -> Result<Option<u64>, DockerfileBuildError> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    parse_limit_value(name, &value.to_string_lossy()).map(Some)
}

fn parse_limit_value(name: &str, value: &str) -> Result<u64, DockerfileBuildError> {
    let parsed = value.parse::<u64>().map_err(|_| {
        DockerfileBuildError::Invalid(format!("{name} must be an unsigned integer"))
    })?;
    if parsed == 0 {
        return Err(DockerfileBuildError::Invalid(format!(
            "{name} must be greater than zero"
        )));
    }
    Ok(parsed)
}

fn apply_build_limits(limits: &BuildLimits) -> io::Result<()> {
    #[cfg(unix)]
    {
        if let Some(bytes) = limits.memory_bytes {
            let limit = nix::libc::rlimit {
                rlim_cur: bytes,
                rlim_max: bytes,
            };
            if unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_AS, &limit) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if let Some(seconds) = limits.cpu_seconds {
            let limit = nix::libc::rlimit {
                rlim_cur: seconds,
                rlim_max: seconds,
            };
            if unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_CPU, &limit) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn reject_cache_symlinks(path: &Path) -> Result<(), DockerfileBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(DockerfileBuildError::Invalid(format!(
            "cache mount contains a symlink: {}",
            path.display()
        )));
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            reject_cache_symlinks(&entry?.path())?;
        }
    }
    Ok(())
}

fn parse_user_spec(value: &str) -> Option<(u32, u32)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.splitn(2, ':');
    let uid = parts.next()?.parse::<u32>().ok()?;
    let gid = parts
        .next()
        .and_then(|g| g.parse::<u32>().ok())
        .unwrap_or(uid);
    Some((uid, gid))
}

fn load_build_seccomp_profile() -> Result<Option<SeccompProfile>, DockerfileBuildError> {
    let enabled = std::env::var("FERROCRATE_BUILD_SECCOMP")
        .map(|val| val != "0")
        .unwrap_or(true);
    if !enabled {
        return Ok(None);
    }
    default_seccomp_profile()
        .map(Some)
        .map_err(|err| DockerfileBuildError::Invalid(format!("build seccomp profile: {err}")))
}

fn setup_build_namespace() -> io::Result<()> {
    use nix::sched::{unshare, CloneFlags};
    unshare(
        CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWNET,
    )
    .map_err(|err| io::Error::other(err.to_string()))
}

fn setup_build_namespace_root() -> io::Result<()> {
    use nix::sched::{unshare, CloneFlags};
    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWNET)
        .map_err(|err| io::Error::other(err.to_string()))
}

fn apply_user_namespace_map() -> io::Result<()> {
    let host_uid = nix::unistd::Uid::current().as_raw();
    let host_gid = nix::unistd::Gid::current().as_raw();
    // Kernel requires setgroups to be disabled before writing gid_map in userns.
    if let Err(err) = fs::write("/proc/self/setgroups", "deny") {
        if err.kind() != io::ErrorKind::NotFound {
            return Err(io::Error::other(format!("setgroups: {err}")));
        }
    }
    fs::write("/proc/self/uid_map", format!("0 {host_uid} 1"))
        .map_err(|err| io::Error::other(format!("uid_map: {err}")))?;
    fs::write("/proc/self/gid_map", format!("0 {host_gid} 1"))
        .map_err(|err| io::Error::other(format!("gid_map: {err}")))
}

fn enter_build_rootfs(rootfs: &Path, workdir: Option<&str>) -> io::Result<()> {
    let path = CString::new(rootfs.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "rootfs path contains NUL"))?;
    let rc = unsafe { nix::libc::chroot(path.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let target = match workdir {
        Some(dir) if !dir.trim().is_empty() => {
            if dir.starts_with('/') {
                dir.to_string()
            } else {
                format!("/{}", dir)
            }
        }
        _ => "/".to_string(),
    };
    std::env::set_current_dir(target)
}

fn apply_build_identity(user: Option<&str>) -> io::Result<()> {
    let (uid, gid) = match user.and_then(parse_user_spec) {
        Some((uid, gid)) => (uid, gid),
        None => (0, 0),
    };
    if uid != 0 || gid != 0 {
        return Err(io::Error::other(
            "build sandbox currently supports only root (0:0) inside user namespace",
        ));
    }
    nix::unistd::setgid(nix::unistd::Gid::from_raw(gid))
        .map_err(|err| io::Error::other(err.to_string()))?;
    nix::unistd::setuid(nix::unistd::Uid::from_raw(uid))
        .map_err(|err| io::Error::other(err.to_string()))
}

fn set_no_new_privileges() -> io::Result<()> {
    let rc = unsafe {
        nix::libc::prctl(
            nix::libc::PR_SET_NO_NEW_PRIVS,
            1 as nix::libc::c_ulong,
            0 as nix::libc::c_ulong,
            0 as nix::libc::c_ulong,
            0 as nix::libc::c_ulong,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
        trimmed.parse::<u64>().ok().map(|v| v * 1_000_000_000)
    }
}

fn resolve_base_image(
    store: &LocalImageStore,
    runtime_dir: &Path,
    base: &str,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
) -> Result<BaseImageInfo, DockerfileBuildError> {
    if base.eq_ignore_ascii_case("scratch") {
        return Ok(BaseImageInfo {
            layers: Vec::new(),
            descriptors: Vec::new(),
            digest: None,
        });
    }

    if resolve_reference(store, base)
        .map_err(DockerfileBuildError::Reference)?
        .is_none()
    {
        pull_image_with_store(runtime_dir, base, store, authority)
            .map_err(|error| DockerfileBuildError::Invalid(error.to_string()))?;
    }
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
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let candidate = root.join(format!("{}-{}-{}", name, std::process::id(), nanos));
    if candidate.exists() {
        let _ = fs::remove_dir_all(&candidate);
    }
    fs::create_dir_all(&candidate)?;
    Ok(candidate)
}

fn copy_context_dir(
    root: &Path,
    src: &Path,
    dst: &Path,
    dockerfile_path: &Path,
    ignore_patterns: &[String],
) -> Result<(), DockerfileBuildError> {
    fs::create_dir_all(dst)?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(src)? {
        entries.push(entry?);
    }
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(root).unwrap_or(&path);
        if path == dockerfile_path {
            continue;
        }
        if should_ignore_context_path(relative, ignore_patterns) {
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
            copy_context_dir(root, &path, &target, dockerfile_path, ignore_patterns)?;
        } else if file_type.is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

fn copy_from_context(
    src_root: &Path,
    dst_root: &Path,
    copies: &[CopySpec],
) -> Result<(), DockerfileBuildError> {
    for spec in copies {
        let dest_root = dst_root.join(spec.dest.trim_start_matches('/'));
        let multiple = spec.srcs.len() > 1 || spec.dest.ends_with('/');
        if multiple {
            fs::create_dir_all(&dest_root)?;
        }
        for src in &spec.srcs {
            let source = src_root.join(src.trim_start_matches('/'));
            let dest = if multiple {
                let name = Path::new(src)
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "src".to_string());
                dest_root.join(name)
            } else {
                dest_root.clone()
            };
            copy_path_recursive_mode(&source, &dest, spec.chmod)?;
        }
    }
    Ok(())
}

fn copy_path_recursive(src: &Path, dst: &Path) -> Result<(), DockerfileBuildError> {
    copy_path_recursive_mode(src, dst, None)
}

fn copy_path_recursive_mode(
    src: &Path,
    dst: &Path,
    chmod: Option<u32>,
) -> Result<(), DockerfileBuildError> {
    let metadata = fs::metadata(src)?;
    if metadata.is_dir() {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            copy_path_recursive_mode(&path, &dst.join(name), chmod)?;
        }
    } else {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(src, dst)?;
    }
    if let Some(mode) = chmod {
        apply_copy_mode(dst, mode)?;
    }
    Ok(())
}

#[cfg(unix)]
fn apply_copy_mode(path: &Path, mode: u32) -> Result<(), DockerfileBuildError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn apply_copy_mode(_path: &Path, _mode: u32) -> Result<(), DockerfileBuildError> {
    Err(DockerfileBuildError::Unsupported(
        "COPY --chmod requires a Unix filesystem".to_string(),
    ))
}

pub fn layer_blob_path(runtime_dir: &Path, digest: &str) -> PathBuf {
    runtime_dir
        .join("images")
        .join("blobs")
        .join(digest.replace(':', "_"))
}

#[cfg(test)]
mod tests {
    use super::{
        build_from_dockerfile_with_store_and_compression, dockerignore_matches, export_build_cache,
        import_build_cache, load_build_cache, parse_limit_value, parse_run, parse_stages,
        prepare_dockerfile_build, prune_build_cache, save_build_cache, BuildCacheEntry,
    };
    use std::collections::HashMap;

    #[test]
    fn build_preparation_is_side_effect_free_and_binds_context() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("runtime");
        let context = temp.path().join("context");
        std::fs::create_dir_all(&context).unwrap();
        let dockerfile = context.join("Dockerfile");
        std::fs::write(&dockerfile, "FROM scratch\nCOPY app /app\n").unwrap();
        std::fs::write(context.join("app"), "one").unwrap();
        let store = LocalImageStore::open(runtime.join("images")).unwrap();

        let first = prepare_dockerfile_build(
            &dockerfile,
            Some("local/app:test"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
        )
        .unwrap();
        std::fs::write(context.join("app"), "two").unwrap();
        let second = prepare_dockerfile_build(
            &dockerfile,
            Some("local/app:test"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
        )
        .unwrap();

        assert_ne!(first.plan_digest(), second.plan_digest());
        assert_eq!(first.canonical_tag(), "registry-1.docker.io/local/app:test");
        assert!(store.list_references().unwrap().is_empty());
        assert!(!runtime.join("build-cache.json").exists());
    }
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
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect("build");
        let layers = resolve_layer_paths_with_store(&runtime_dir, &result.reference, &store)
            .expect("layers");
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
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect("build");

        let cache = load_build_cache(&runtime_dir).expect("load cache");
        assert_eq!(cache.len(), 1);
        let entry = cache.values().next().expect("cache entry");
        assert!(!entry.cache_key.is_empty());
        assert!(entry.created_at_unix > 0);
        assert!(!entry.context_digest.is_empty());
        assert!(!entry.dockerfile_digest.is_empty());
        assert_eq!(entry.base_digests, vec!["scratch"]);
        assert!(!runtime_dir.join("images/build-cache.json.tmp").exists());
    }

    #[test]
    fn cache_entry_records_source_provenance_when_context_changes() {
        let temp = tempfile::tempdir().unwrap();
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\nCOPY . /\n").unwrap();
        fs::write(temp.path().join("hello.txt"), "one").unwrap();
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).unwrap();
        let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();
        let first = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/test:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &authority,
        )
        .unwrap();
        let first_cache = load_build_cache(&runtime).unwrap();
        let first_entry = first_cache.values().next().unwrap().clone();
        fs::write(temp.path().join("hello.txt"), "two").unwrap();
        let second = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/test:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &authority,
        )
        .unwrap();
        assert_ne!(first.layer_digest, second.layer_digest);
        assert!(load_build_cache(&runtime)
            .unwrap()
            .values()
            .any(|entry| entry.context_digest != first_entry.context_digest));
    }

    #[test]
    fn prunes_oldest_build_cache_entries_deterministically() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().to_path_buf();
        let mut cache = HashMap::new();
        for (key, timestamp) in [("old", 1), ("middle", 2), ("new", 3)] {
            cache.insert(
                key.to_string(),
                BuildCacheEntry {
                    cache_key: key.to_string(),
                    created_at_unix: timestamp,
                    context_digest: String::new(),
                    dockerfile_digest: String::new(),
                    base_digests: Vec::new(),
                    layer_digest: format!("sha256:{key}"),
                    layer_size: 1,
                    layer_media_type: "application/octet-stream".to_string(),
                    config_digest: format!("sha256:config-{key}"),
                    config_json: "{}".to_string(),
                    manifest_json: "{}".to_string(),
                },
            );
        }
        save_build_cache(&runtime, &cache).unwrap();
        assert_eq!(prune_build_cache(&runtime, 1).unwrap(), 2);
        let retained = load_build_cache(&runtime).unwrap();
        assert!(retained.contains_key("new"));
        assert_eq!(retained.len(), 1);
    }

    #[test]
    fn exports_and_imports_build_cache_metadata_atomically() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let mut cache = HashMap::new();
        cache.insert(
            "key".to_string(),
            BuildCacheEntry {
                cache_key: "key".to_string(),
                created_at_unix: 1,
                context_digest: String::new(),
                dockerfile_digest: String::new(),
                base_digests: Vec::new(),
                layer_digest: "sha256:layer".to_string(),
                layer_size: 1,
                layer_media_type: "application/octet-stream".to_string(),
                config_digest: "sha256:config".to_string(),
                config_json: "{}".to_string(),
                manifest_json: "{}".to_string(),
            },
        );
        save_build_cache(source.path(), &cache).unwrap();
        let export = source.path().join("export.json");
        export_build_cache(source.path(), &export).unwrap();
        assert_eq!(import_build_cache(target.path(), &export).unwrap(), 1);
        assert_eq!(load_build_cache(target.path()).unwrap().len(), 1);
    }

    #[test]
    fn shell_instruction_applies_to_shell_form_run_cmd_and_entrypoint() {
        let dockerfile = r#"
        FROM scratch
        SHELL ["/bin/bash", "-lc"]
        RUN echo hi
        CMD echo hello
        ENTRYPOINT echo bye
        "#;
        let stages = parse_stages(dockerfile).expect("parse stages");
        let stage = stages.last().expect("stage");
        assert_eq!(stage.run.len(), 1);
        assert_eq!(stage.run[0].args, vec!["/bin/bash", "-lc", "echo hi"]);
        assert_eq!(
            stage.cmd.clone().expect("cmd"),
            vec!["/bin/bash", "-lc", "echo hello"]
        );
        assert_eq!(
            stage.entrypoint.clone().expect("entrypoint"),
            vec!["/bin/bash", "-lc", "echo bye"]
        );
    }

    #[test]
    fn run_mount_features_fail_closed_until_secret_handling_exists() {
        for mount_type in ["secret", "ssh"] {
            let error = parse_run(
                &format!("--mount=type={mount_type} echo value"),
                &["/bin/sh".into(), "-c".into()],
            )
            .expect_err("unsupported mount must not be executed");
            assert!(error.to_string().contains("not supported"));
        }
    }

    #[test]
    fn cache_mounts_parse_with_safe_identity_and_target() {
        let run = parse_run(
            "--mount=type=cache,target=/root/.cache,id=compiler echo value",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("cache mount parses");
        assert_eq!(run.cache_mounts.len(), 1);
        assert_eq!(run.cache_mounts[0].target, "/root/.cache");
        assert_eq!(run.cache_mounts[0].id, "compiler");

        for invalid in [
            "--mount=type=cache,target=relative echo value",
            "--mount=type=cache,target=/tmp/../escape echo value",
            "--mount=type=cache,target=/tmp,id=bad/slash echo value",
        ] {
            assert!(parse_run(invalid, &["/bin/sh".into(), "-c".into()]).is_err());
        }
    }

    #[test]
    fn build_limit_values_are_strictly_positive_unsigned_integers() {
        assert_eq!(parse_limit_value("LIMIT", "4096").unwrap(), 4096);
        for value in ["", "0", "-1", "1.5", "1e3"] {
            assert!(
                parse_limit_value("LIMIT", value).is_err(),
                "accepted {value:?}"
            );
        }
    }

    #[test]
    fn copy_chmod_is_parsed_and_unsupported_flags_fail_deterministically() {
        let stages = parse_stages("FROM scratch\nCOPY --chmod=755 app /app\n").unwrap();
        assert_eq!(stages[0].copy_paths[0].chmod, Some(0o755));

        let error = parse_stages("FROM scratch\nCOPY --chown=1000:1000 app /app\n")
            .expect_err("unsupported copy flags must not be silently ignored");
        assert!(error.to_string().contains("COPY flag --chown=1000:1000"));

        let error = parse_stages("FROM scratch\nCOPY --chmod=999 app /app\n")
            .expect_err("invalid modes must be rejected");
        assert!(error.to_string().contains("invalid COPY --chmod mode"));
    }

    #[test]
    fn unsupported_directives_fail_instead_of_being_silently_ignored() {
        for directive in [
            "STOPSIGNAL SIGTERM",
            "MAINTAINER legacy",
            "ONBUILD RUN echo hi",
        ] {
            let error = parse_stages(&format!("FROM scratch\n{directive}\n"))
                .expect_err("unsupported directive must fail deterministically");
            assert!(error.to_string().contains("instruction"), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn copy_chmod_applies_mode_to_materialized_files() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        std::fs::write(&source, "secret").unwrap();
        super::copy_from_context(
            temp.path(),
            &destination,
            &[super::CopySpec {
                srcs: vec!["source".into()],
                dest: "/materialized".into(),
                chmod: Some(0o640),
            }],
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(destination.join("materialized"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }

    #[test]
    fn dockerignore_pattern_matching_covers_exact_prefix_and_wildcards() {
        assert!(dockerignore_matches("target", "target"));
        assert!(dockerignore_matches("target", "target/file.txt"));
        assert!(dockerignore_matches("logs/", "logs/app.log"));
        assert!(dockerignore_matches("*.tmp", "cache/build.tmp"));
        assert!(!dockerignore_matches("src/", "tests/main.rs"));
    }
}
