#[cfg(target_os = "linux")]
use crate::capabilities::set_capabilities;
use crate::image_fetch::{pull_image_with_store, resolve_layer_paths_with_store};
use crate::image_manifest::parse_image_manifest;
use crate::image_manifest::{
    Descriptor, ImageManifest, OCI_IMAGE_CONFIG_MEDIA_TYPE, OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE,
    OCI_IMAGE_LAYER_MEDIA_TYPE, OCI_IMAGE_LAYER_ZSTD_MEDIA_TYPE, OCI_IMAGE_MANIFEST_MEDIA_TYPE,
};
use crate::image_store::LocalImageStore;
use crate::image_tagging::{
    canonicalize_reference, normalize_selector, resolve_reference, ImageSelector,
};
use crate::layer_compression::{
    compress_bytes_gzip, compress_bytes_zstd, CompressionFormat, LayerCompressionError,
};
use crate::registry::{RegistryAuth, RegistryClient};
#[cfg(target_os = "linux")]
use crate::rootfs::{apply_layer_tar, construct_rootfs_with_dedup};
#[cfg(target_os = "linux")]
use crate::seccomp::{apply_seccomp_profile, default_seccomp_profile, SeccompProfile};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use lzma_rust2::XzReader;
#[cfg(unix)]
use nix::mount::{mount, MsFlags};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::ffi::CString;
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tar::{Archive, Builder};
use thiserror::Error;

const MAX_ADD_REMOTE_SIZE: u64 = 64 * 1024 * 1024;

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
    #[error("image build authorization binding failed: {0}")]
    Authorization(String),
    #[error("registry error: {0}")]
    Registry(#[from] crate::registry::RegistryError),
    #[error("ADD remote fetch error: {0}")]
    RemoteFetch(#[from] reqwest::Error),
    #[error("build cancelled: {0}")]
    Cancelled(String),
    #[error("build limit exceeded: {0}")]
    LimitExceeded(String),
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
    named_contexts: HashMap<String, PathBuf>,
    build_args: HashMap<String, String>,
    execution_options: DockerfileExecutionOptions,
    stage_dependencies: Vec<Vec<usize>>,
    stage_batches: Vec<Vec<usize>>,
    stage_identities: Vec<String>,
    plan_digest: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DockerfileExecutionOptions {
    /// BuildKit frontend target platform. This remains separate from automatic
    /// build arguments because users may override `TARGET*` arguments without
    /// changing the output image's platform.
    pub target_platform: Option<String>,
    pub shm_size: Option<u64>,
    pub ulimits: Vec<DockerfileUlimit>,
    pub cgroup_parent: Option<String>,
    pub memory: Option<u64>,
    pub memory_swap: Option<i64>,
    pub cpu_shares: Option<u64>,
    pub cpu_quota: Option<u64>,
    pub cpu_period: Option<u64>,
    pub cpuset_cpus: Option<String>,
    pub cpuset_mems: Option<String>,
    pub pids_limit: Option<u64>,
    /// Resolved BuildKit SOURCE_DATE_EPOCH used for config and layer clamping.
    pub source_date_epoch: Option<u64>,
    /// `Some([])` disables cache for every stage; names select specific stages.
    pub no_cache: Option<Vec<String>>,
    pub network_mode: DockerfileNetworkMode,
    pub allow_network_host: bool,
    pub allow_security_insecure: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DockerfileUlimit {
    pub name: String,
    pub soft: i64,
    pub hard: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DockerfileNetworkMode {
    #[default]
    Sandbox,
    None,
    Host,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum DockerfileSecurityMode {
    #[default]
    Sandbox,
    Insecure,
}

fn dockerfile_default_capabilities() -> Vec<caps::Capability> {
    use caps::Capability::*;
    vec![
        CAP_CHOWN,
        CAP_DAC_OVERRIDE,
        CAP_FOWNER,
        CAP_FSETID,
        CAP_KILL,
        CAP_SETGID,
        CAP_SETUID,
        CAP_SETPCAP,
        CAP_NET_BIND_SERVICE,
        CAP_NET_RAW,
        CAP_SYS_CHROOT,
        CAP_MKNOD,
        CAP_AUDIT_WRITE,
        CAP_SETFCAP,
    ]
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct BuildDeviceNode {
    path: PathBuf,
    kind: nix::sys::stat::SFlag,
    major: u64,
    minor: u64,
}

#[cfg(target_os = "linux")]
fn next_free_loop_device() -> io::Result<u32> {
    let control = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/loop-control")?;
    const LOOP_CTL_GET_FREE: nix::libc::c_ulong = 0x4C82;
    let result = unsafe { nix::libc::ioctl(control.as_raw_fd(), LOOP_CTL_GET_FREE) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(result).map_err(|_| io::Error::other("free loop device id exceeds u32"))
}

#[cfg(target_os = "linux")]
fn buildkit_insecure_device_nodes(free_loop_id: Option<u32>) -> Vec<BuildDeviceNode> {
    use nix::sys::stat::SFlag;
    let character = |path: &str, major, minor| BuildDeviceNode {
        path: path.into(),
        kind: SFlag::S_IFCHR,
        major,
        minor,
    };
    let mut devices = vec![
        character("null", 1, 3),
        character("zero", 1, 5),
        character("full", 1, 7),
        character("random", 1, 8),
        character("urandom", 1, 9),
        character("tty", 5, 0),
        character("kmsg", 1, 11),
        character("cuse", 10, 203),
        character("fuse", 10, 229),
        character("kvm", 10, 232),
        character("net/tun", 10, 200),
        character("loop-control", 10, 237),
    ];
    let last_loop = free_loop_id.unwrap_or(0).saturating_add(7);
    devices.extend((0..=last_loop).map(|minor| BuildDeviceNode {
        path: format!("loop{minor}").into(),
        kind: SFlag::S_IFBLK,
        major: 7,
        minor: u64::from(minor),
    }));
    devices
}

#[cfg(target_os = "linux")]
fn mount_rootful_insecure_devices(rootfs_dev: &Path) -> io::Result<()> {
    mount(
        None::<&str>,
        rootfs_dev,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=755,size=1m"),
    )
    .map_err(|error| io::Error::other(format!("mount insecure build /dev: {error}")))?;
    for directory in ["net", "pts", "shm"] {
        fs::create_dir_all(rootfs_dev.join(directory))?;
    }
    let free_loop_id = next_free_loop_device().ok();
    for device in buildkit_insecure_device_nodes(free_loop_id) {
        nix::sys::stat::mknod(
            &rootfs_dev.join(&device.path),
            device.kind,
            nix::sys::stat::Mode::from_bits_truncate(0o666),
            nix::sys::stat::makedev(device.major, device.minor),
        )
        .map_err(|error| {
            io::Error::other(format!(
                "create insecure build device /dev/{}: {error}",
                device.path.display()
            ))
        })?;
    }
    Ok(())
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

    /// Return the zero-based stage dependencies used to construct each stage.
    /// Independent stages have empty/disjoint dependency lists and can be
    /// scheduled concurrently by a future graph executor.
    pub fn stage_dependencies(&self) -> &[Vec<usize>] {
        &self.stage_dependencies
    }

    /// Return deterministic topological batches. Stages in one batch depend
    /// only on earlier batches and are candidates for concurrent execution.
    pub fn stage_batches(&self) -> &[Vec<usize>] {
        &self.stage_batches
    }

    /// Return the content-addressed identity of every stage: a digest of the
    /// stage instructions, the context it consumes, its base image, and the
    /// identities of the stages it copies from. Two builds of the same stage
    /// inputs produce the same identity; editing one stage changes only that
    /// stage's identity and the identities of its descendants.
    pub fn stage_identities(&self) -> &[String] {
        &self.stage_identities
    }
}

pub fn prepare_dockerfile_build(
    dockerfile_path: &Path,
    tag: Option<&str>,
    runtime_dir: &Path,
    compression: CompressionFormat,
    store: &LocalImageStore,
) -> Result<ImageBuildPlan, DockerfileBuildError> {
    prepare_dockerfile_build_with_contexts(dockerfile_path, tag, runtime_dir, compression, store, &HashMap::new())
}

pub fn prepare_dockerfile_build_with_contexts_and_build_args(
    dockerfile_path: &Path, tag: Option<&str>, runtime_dir: &Path, compression: CompressionFormat,
    store: &LocalImageStore, named_contexts: &HashMap<String, PathBuf>, build_args: &HashMap<String, String>,
) -> Result<ImageBuildPlan, DockerfileBuildError> {
    prepare_dockerfile_build_with_contexts_and_build_args_and_options(
        dockerfile_path,
        tag,
        runtime_dir,
        compression,
        store,
        named_contexts,
        build_args,
        &DockerfileExecutionOptions::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_dockerfile_build_with_contexts_and_build_args_and_options(
    dockerfile_path: &Path,
    tag: Option<&str>,
    runtime_dir: &Path,
    compression: CompressionFormat,
    store: &LocalImageStore,
    named_contexts: &HashMap<String, PathBuf>,
    build_args: &HashMap<String, String>,
    execution_options: &DockerfileExecutionOptions,
) -> Result<ImageBuildPlan, DockerfileBuildError> {
    prepare_dockerfile_build_with_contexts_and_build_args_inner(
        dockerfile_path,
        tag,
        runtime_dir,
        compression,
        store,
        named_contexts,
        build_args,
        execution_options,
    )
}

/// Return registry-backed `FROM` references in first-use order.
///
/// Scratch stages and references to aliases declared by earlier stages are
/// build-graph inputs, not registry images, and are deliberately excluded.
pub fn dockerfile_external_base_images(
    dockerfile_path: &Path,
) -> Result<Vec<String>, DockerfileBuildError> {
    dockerfile_external_base_images_with_build_args(dockerfile_path, &HashMap::new())
}

pub fn dockerfile_external_base_images_with_build_args(
    dockerfile_path: &Path,
    build_args: &HashMap<String, String>,
) -> Result<Vec<String>, DockerfileBuildError> {
    if !dockerfile_path.exists() {
        return Err(DockerfileBuildError::MissingDockerfile(
            dockerfile_path.display().to_string(),
        ));
    }
    let stages = parse_stages_with_build_args(&fs::read_to_string(dockerfile_path)?, build_args)?;
    let mut aliases = HashSet::new();
    let mut seen = HashSet::new();
    let mut bases = Vec::new();
    for stage in stages {
        if !stage.base.eq_ignore_ascii_case("scratch")
            && !aliases.contains(&stage.base)
            && seen.insert(stage.base.clone())
        {
            bases.push(stage.base.clone());
        }
        if let Some(name) = stage.name {
            aliases.insert(name);
        }
    }
    Ok(bases)
}

/// Return image references used as external `COPY --from` sources.
pub fn dockerfile_external_copy_images_with_build_args(
    dockerfile_path: &Path,
    build_args: &HashMap<String, String>,
) -> Result<Vec<String>, DockerfileBuildError> {
    if !dockerfile_path.exists() {
        return Err(DockerfileBuildError::MissingDockerfile(
            dockerfile_path.display().to_string(),
        ));
    }
    let stages = parse_stages_with_build_args(&fs::read_to_string(dockerfile_path)?, build_args)?;
    let stage_names = stages
        .iter()
        .filter_map(|stage| stage.name.as_deref())
        .map(str::to_ascii_lowercase)
        .collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    let mut images = Vec::new();
    for stage in stages {
        for copy in stage.copy_from.iter().chain(stage.copy_from_after_run.iter()) {
            if copy.from.parse::<usize>().is_err()
                && !stage_names.contains(&copy.from.to_ascii_lowercase())
                && seen.insert(copy.from.clone())
            {
                images.push(copy.from.clone());
            }
        }
    }
    Ok(images)
}

pub fn prepare_dockerfile_build_with_contexts(
    dockerfile_path: &Path,
    tag: Option<&str>,
    runtime_dir: &Path,
    compression: CompressionFormat,
    store: &LocalImageStore,
    named_contexts: &HashMap<String, PathBuf>,
) -> Result<ImageBuildPlan, DockerfileBuildError> {
    prepare_dockerfile_build_with_contexts_and_build_args_inner(
        dockerfile_path,
        tag,
        runtime_dir,
        compression,
        store,
        named_contexts,
        &HashMap::new(),
        &DockerfileExecutionOptions::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_dockerfile_build_with_contexts_and_build_args_inner(
    dockerfile_path: &Path, tag: Option<&str>, runtime_dir: &Path, compression: CompressionFormat,
    store: &LocalImageStore, named_contexts: &HashMap<String, PathBuf>, build_args: &HashMap<String, String>,
    execution_options: &DockerfileExecutionOptions,
) -> Result<ImageBuildPlan, DockerfileBuildError> {
    if !dockerfile_path.exists() {
        return Err(DockerfileBuildError::MissingDockerfile(
            dockerfile_path.display().to_string(),
        ));
    }
    let dockerfile = fs::read_to_string(dockerfile_path)?;
    let stages = parse_stages_with_build_args(&dockerfile, build_args)?;
    let context_dir = dockerfile_path
        .parent()
        .ok_or_else(|| DockerfileBuildError::Invalid("invalid dockerfile path".to_string()))?;
    let context_digest = build_context_binding_digest(
        &hash_context_dir_excluding(context_dir, dockerfile_path, Some(runtime_dir))?,
        named_contexts,
    )?;
    let canonical_tag = canonicalize_reference(tag.unwrap_or("local/build:latest"))?;
    let stage_dependencies = build_stage_dependency_graph(&stages, named_contexts)?;
    let stage_batches = build_stage_execution_batches(&stage_dependencies)?;
    let mut base_digests = Vec::with_capacity(stages.len());
    let stage_aliases = earlier_stage_aliases(&stages)?;
    for (index, stage) in stages.iter().enumerate() {
        if stage.base.eq_ignore_ascii_case("scratch")
            || stage_aliases[index].contains_key(&stage.base.to_ascii_lowercase())
        {
            base_digests.push((stage.base.clone(), None));
        } else {
            let record = resolve_reference(store, &stage.base)?.ok_or_else(|| {
                DockerfileBuildError::Invalid(format!("base image not found: {}", stage.base))
            })?;
            base_digests.push((stage.base.clone(), Some(record.digest)));
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
    for (key, value) in BTreeMap::from_iter(build_args.iter()) { hash.update(key.as_bytes()); hash.update(value.as_bytes()); }
    append_execution_options_identity(&mut hash, execution_options);
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
    hash.update((stage_dependencies.len() as u64).to_be_bytes());
    for dependencies in &stage_dependencies {
        hash.update((dependencies.len() as u64).to_be_bytes());
        for dependency in dependencies {
            hash.update((*dependency as u64).to_be_bytes());
        }
    }
    let stage_base_digests: Vec<String> = base_digests
        .iter()
        .map(|(_, digest)| digest.clone().unwrap_or_else(|| "scratch".to_string()))
        .collect();
    let stage_identities = stage_content_identities(
        &stages,
        &stage_base_digests,
        &context_digest,
        &stage_dependencies,
        compression,
    )?;
    hash.update((stage_identities.len() as u64).to_be_bytes());
    for identity in &stage_identities {
        hash.update((identity.len() as u64).to_be_bytes());
        hash.update(identity.as_bytes());
    }
    Ok(ImageBuildPlan {
        dockerfile_path: dockerfile_path.to_path_buf(),
        runtime_dir: runtime_dir.to_path_buf(),
        canonical_tag,
        compression,
        context_digest,
        dockerfile_digest,
        base_digests,
        named_contexts: canonicalize_named_contexts(named_contexts)?,
        build_args: build_args.clone(),
        execution_options: execution_options.clone(),
        stage_dependencies,
        stage_batches,
        stage_identities,
        plan_digest: hash.finalize().into(),
    })
}

fn append_execution_options_identity(
    hash: &mut Sha256,
    options: &DockerfileExecutionOptions,
) {
    let encoded = format!("{options:?}");
    hash.update((encoded.len() as u64).to_be_bytes());
    hash.update(encoded.as_bytes());
}

pub struct BuildResult {
    pub reference: String,
    pub layer_digest: String,
    pub config_digest: String,
}

#[derive(Debug)]
struct BuiltStage {
    root: PathBuf,
    name: Option<String>,
    layer_digest: String,
    layer_media_type: String,
    layer_size: i64,
    /// The context layer precedes a RUN delta in the final image.  It is
    /// absent for stages without RUN because `layer_*` is then the context
    /// layer itself.
    context_layer: Option<StageLayer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StageLayer {
    digest: String,
    media_type: String,
    size: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StageCheckpoint {
    build_key: String,
    layer_digest: String,
    layer_media_type: String,
    layer_size: i64,
    #[serde(default)]
    context_layer: Option<StageLayer>,
}

#[derive(Debug, Clone)]
struct BaseImageInfo {
    layers: Vec<PathBuf>,
    descriptors: Vec<Descriptor>,
    digest: Option<String>,
    onbuild: Vec<String>,
    env: Vec<String>,
    config: BaseConfig,
}

/// The parts of a base image's config a stage inherits when its Dockerfile does
/// not set them. A Dockerfile that adds only a COPY previously produced an image
/// with no command at all, so `run` had nothing to start (S24).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct BaseConfig {
    architecture: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
    variant: Option<String>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    workdir: Option<String>,
    user: Option<String>,
    stop_signal: Option<String>,
    exposed_ports: Vec<String>,
    volumes: Vec<String>,
    labels: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Layer digests for every stage in Dockerfile execution order. Keeping
    /// the complete stage graph in cache provenance prevents an imported
    /// final-layer record from being mistaken for a complete build graph.
    #[serde(default)]
    stage_layer_digests: Vec<String>,
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
    build_from_dockerfile_with_store_and_compression_with_contexts(
        dockerfile_path,
        tag,
        runtime_dir,
        compression,
        store,
        authority,
        &HashMap::new(),
    )
}

pub(crate) fn build_from_dockerfile_with_store_and_compression_with_contexts(
    dockerfile_path: &Path,
    tag: Option<&str>,
    runtime_dir: &Path,
    compression: CompressionFormat,
    store: &LocalImageStore,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
    named_contexts: &HashMap<String, PathBuf>,
) -> Result<BuildResult, DockerfileBuildError> {
    build_from_dockerfile_with_store_and_compression_with_contexts_and_secrets(
        dockerfile_path,
        tag,
        runtime_dir,
        compression,
        store,
        authority,
        named_contexts,
        &HashMap::new(),
        None,
    )
}

fn stage_checkpoint_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("build").join("stage-checkpoints.json")
}

fn load_stage_checkpoints(
    runtime_dir: &Path,
) -> Result<HashMap<usize, StageCheckpoint>, DockerfileBuildError> {
    let path = stage_checkpoint_path(runtime_dir);
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() || metadata.len() > 4 * 1024 * 1024 {
        return Err(DockerfileBuildError::Invalid(
            "stage checkpoint must be a bounded regular file".to_string(),
        ));
    }
    serde_json::from_slice(&fs::read(path)?).map_err(|error| {
        DockerfileBuildError::Invalid(format!("stage checkpoint is malformed: {error}"))
    })
}

fn save_stage_checkpoints(
    runtime_dir: &Path,
    checkpoints: &HashMap<usize, StageCheckpoint>,
) -> Result<(), DockerfileBuildError> {
    let path = stage_checkpoint_path(runtime_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes =
        serde_json::to_vec(checkpoints).map_err(|error| io::Error::other(error.to_string()))?;
    let temporary = path.with_extension(format!(
        "json.tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, &path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn build_journal_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("build").join("journal.json")
}

/// Lifecycle state recorded for one build attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BuildJournalState {
    Running,
    Cancelled,
    Failed,
    Complete,
}

/// Build record binding source, context, and image identities so an
/// interrupted or retried build can be verified before it resumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BuildJournal {
    cache_key: String,
    context_digest: String,
    dockerfile_digest: String,
    base_digests: Vec<String>,
    image_reference: String,
    #[serde(default)]
    authorization_plan_digest: Option<String>,
    state: BuildJournalState,
    #[serde(default)]
    completed_stages: Vec<usize>,
    /// Full output of the failing RUN. Kept on disk for diagnosis; CLI output
    /// may be abbreviated but the journal must not discard the evidence.
    #[serde(default)]
    failure_output: Option<String>,
}

impl BuildJournal {
    /// The resume identity: everything that determines the stage checkpoints.
    /// A changed context, Dockerfile, or base image invalidates the journal
    /// and its checkpoints so a retry never resumes stale state.
    fn identity_matches(
        &self,
        cache_key: &str,
        context_digest: &str,
        dockerfile_digest: &str,
        base_digests: &[String],
    ) -> bool {
        self.cache_key == cache_key
            && self.context_digest == context_digest
            && self.dockerfile_digest == dockerfile_digest
            && self.base_digests == base_digests
    }
}

fn load_build_journal(runtime_dir: &Path) -> Result<Option<BuildJournal>, DockerfileBuildError> {
    let path = build_journal_path(runtime_dir);
    if !path.exists() {
        return Ok(None);
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() {
        return Err(DockerfileBuildError::Invalid(
            "build journal must be a regular file".to_string(),
        ));
    }
    serde_json::from_slice(&fs::read(&path)?)
        .map(Some)
        .map_err(|error| {
            DockerfileBuildError::Invalid(format!(
                "build journal is malformed: {error}; remove {} to start a fresh build",
                path.display()
            ))
        })
}

fn save_build_journal(
    runtime_dir: &Path,
    journal: &BuildJournal,
) -> Result<(), DockerfileBuildError> {
    let path = build_journal_path(runtime_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(journal).map_err(|error| io::Error::other(error.to_string()))?;
    let temporary = path.with_extension(format!(
        "json.tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, &path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn restore_stage_from_checkpoint(
    runtime_dir: &Path,
    idx: usize,
    base_info: &BaseImageInfo,
    inherited_root: Option<&Path>,
    checkpoint: &StageCheckpoint,
) -> Result<Option<BuiltStage>, DockerfileBuildError> {
    if checkpoint.layer_size < 0 {
        return Ok(None);
    }
    let layer_path = layer_blob_path(runtime_dir, &checkpoint.layer_digest);
    let metadata = match fs::metadata(&layer_path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(None),
    };
    if !metadata.is_file()
        || metadata.len() != checkpoint.layer_size as u64
        || !file_matches_digest(&layer_path, &checkpoint.layer_digest)
    {
        return Ok(None);
    }
    // Checkpoint restore may run beside another build using the same runtime.
    // Its root must therefore be per-attempt, just like the context scratch.
    let stage_root = create_build_dir(runtime_dir, &format!("stage-{idx}"))?;
    let cas_root = runtime_dir.join("images").join("cas").join("blake3");
    if let Some(parent_root) = inherited_root {
        copy_rootfs_contents(parent_root, &stage_root)?;
    } else if !base_info.layers.is_empty() {
        construct_rootfs_with_dedup(&stage_root, &base_info.layers, &cas_root)
            .map_err(|error| DockerfileBuildError::Invalid(error.to_string()))?;
    } else {
        fs::create_dir_all(&stage_root)?;
    }
    if let Some(context_layer) = &checkpoint.context_layer {
        let context_path = layer_blob_path(runtime_dir, &context_layer.digest);
        let metadata = match fs::metadata(&context_path) {
            Ok(metadata) => metadata,
            Err(_) => return Ok(None),
        };
        if !metadata.is_file()
            || metadata.len() != context_layer.size as u64
            || !file_matches_digest(&context_path, &context_layer.digest)
        {
            return Ok(None);
        }
        apply_layer_tar(&stage_root, &context_path)
            .map_err(|error| DockerfileBuildError::Invalid(error.to_string()))?;
    }
    apply_layer_tar(&stage_root, &layer_path)
        .map_err(|error| DockerfileBuildError::Invalid(error.to_string()))?;
    Ok(Some(BuiltStage {
        root: stage_root,
        name: None,
        layer_digest: checkpoint.layer_digest.clone(),
        layer_media_type: checkpoint.layer_media_type.clone(),
        layer_size: checkpoint.layer_size,
        context_layer: checkpoint.context_layer.clone(),
    }))
}

#[allow(clippy::too_many_arguments)]
fn build_one_stage(
    idx: usize,
    stage: &StageSpec,
    base_info: &BaseImageInfo,
    runtime_dir: &Path,
    context_dir: &Path,
    dockerfile_path: &Path,
    compression: CompressionFormat,
    ignore_patterns: &[String],
    named_contexts: &HashMap<String, PathBuf>,
    secrets: &HashMap<String, PathBuf>,
    stage_roots: &[PathBuf],
    stage_names: &HashMap<String, PathBuf>,
    inherited_root: Option<&Path>,
    inherited_workdir: Option<&str>,
    control: &BuildControl,
    execution_options: &DockerfileExecutionOptions,
) -> Result<BuiltStage, DockerfileBuildError> {
    // Stage roots are mutable during COPY and RUN. A fixed `stage-{idx}`
    // directory lets concurrent builds overlay each other's context; allocate
    // a private one for this attempt instead.
    let stage_root = create_build_dir(runtime_dir, &format!("stage-{idx}"))?;
    let cas_root = runtime_dir.join("images").join("cas").join("blake3");
    if let Some(parent_root) = inherited_root {
        copy_rootfs_contents(parent_root, &stage_root)?;
    } else if !base_info.layers.is_empty() {
        construct_rootfs_with_dedup(&stage_root, &base_info.layers, &cas_root)
            .map_err(|err| DockerfileBuildError::Invalid(err.to_string()))?;
    } else {
        fs::create_dir_all(&stage_root)?;
    }
    let workdir = stage
        .workdir
        .as_deref()
        .or(inherited_workdir)
        .or(base_info.config.workdir.as_deref());
    let context_root = create_build_dir(runtime_dir, &format!("context-{idx}"))?;
    if stage.copy_paths.is_empty() {
        copy_context_dir(
            context_dir,
            context_dir,
            &context_root,
            dockerfile_path,
            ignore_patterns,
        )?;
    } else {
        // Docker applies .dockerignore before evaluating every COPY source,
        // including the common `COPY . .` spelling.  Keep an isolated,
        // filtered source tree so explicit COPYs cannot bypass that contract.
        let filtered_context = create_build_dir(runtime_dir, &format!("filtered-context-{idx}"))?;
        copy_context_dir(
            context_dir,
            context_dir,
            &filtered_context,
            dockerfile_path,
            ignore_patterns,
        )?;
        let mut copy_paths = stage.copy_paths.clone();
        for spec in &mut copy_paths {
            spec.dest = resolve_copy_destination(workdir, &spec.dest);
            if let Some(owner) = spec.owner.as_ref() {
                let (uid, gid) = resolve_copy_owner(&stage_root, owner)?;
                spec.owner = Some(CopyOwner::Numeric(uid, gid));
            }
        }
        copy_from_context(&filtered_context, &context_root, &copy_paths)?;
    }
    for copy in &stage.copy_from {
        let source_root = resolve_stage_root(stage_roots, stage_names, named_contexts, &copy.from)
            .ok_or_else(|| {
                DockerfileBuildError::Invalid(format!("unknown COPY --from stage: {}", copy.from))
            })?;
        let destination = resolve_copy_destination(workdir, &copy.dest);
        let destination_root = safe_context_destination(&context_root, &destination)?;
        if copy.srcs.len() > 1 {
            fs::create_dir_all(&destination_root)?;
        }
        for source_path in &copy.srcs {
            let source = safe_context_source(&source_root, source_path)?;
            let dest = if copy.srcs.len() > 1 {
                destination_root.join(source.file_name().unwrap_or_default())
            } else {
                destination_root.clone()
            };
            copy_path_recursive(&source, &dest)?;
            if let Some(owner) = copy.owner.as_ref() {
                let (uid, gid) = resolve_copy_owner(&stage_root, owner)?;
                let resolved = CopyOwner::Numeric(uid, gid);
                apply_copy_owner_recursive(&dest, &resolved)?;
            }
        }
    }

    let (layer_bytes, mut layer_media_type) = build_layer_from_dir(
        &context_root,
        Some(dockerfile_path),
        compression,
        execution_options.source_date_epoch,
    )?;
    let mut layer_digest = sha256_digest_bytes(&layer_bytes);
    let mut layer_size = layer_bytes.len() as i64;
    write_blob(runtime_dir, &layer_digest, &layer_bytes)?;
    let layer_path = layer_blob_path(runtime_dir, &layer_digest);
    apply_layer_tar(&stage_root, &layer_path)
        .map_err(|err| DockerfileBuildError::Invalid(err.to_string()))?;

    let context_layer = if !stage.run.is_empty() {
        Some(StageLayer {
            digest: layer_digest.clone(),
            media_type: layer_media_type.clone(),
            size: layer_size,
        })
    } else {
        None
    };

    if !stage.run.is_empty() {
        // The context layer has already been applied to the rootfs.  RUN must
        // produce its own change set, not repeat that context layer (and never
        // repeat the base filesystem).
        let stage_baseline = snapshot_stage_root(&stage_root)?;
        apply_stage_workdir(&stage_root, workdir)?;
        let copy_from_after_run_index = stage
            .copy_from_after_run_index
            .unwrap_or(stage.run.len());
        run_stage_commands(
            &stage_root,
            &stage.run[..copy_from_after_run_index],
            &stage_environment(base_info, &stage.env),
            workdir,
            stage.user.as_deref(),
            &runtime_dir
                .join("build")
                .join("cache")
                .join(format!("stage-{idx}")),
            secrets,
            context_dir,
            control,
            execution_options,
        )?;
        // Preserve Dockerfile ordering for artifacts copied after a RUN. In
        // particular, `npm ci` removes sqlite3's build directory, so its
        // native binding must be copied only after that command completes.
        for copy in &stage.copy_from_after_run {
            let source_root = resolve_stage_root(stage_roots, stage_names, named_contexts, &copy.from)
                .ok_or_else(|| {
                    DockerfileBuildError::Invalid(format!("unknown COPY --from stage: {}", copy.from))
                })?;
            let destination = resolve_copy_destination(workdir, &copy.dest);
            let destination_root = safe_context_destination(&stage_root, &destination)?;
            if copy.srcs.len() > 1 {
                fs::create_dir_all(&destination_root)?;
            }
            for source_path in &copy.srcs {
                let source = safe_context_source(&source_root, source_path)?;
                let dest = if copy.srcs.len() > 1 {
                    destination_root.join(source.file_name().unwrap_or_default())
                } else {
                    destination_root.clone()
                };
                copy_path_recursive(&source, &dest)?;
                if let Some(owner) = copy.owner.as_ref() {
                    let (uid, gid) = resolve_copy_owner(&stage_root, owner)?;
                    apply_copy_owner_recursive(&dest, &CopyOwner::Numeric(uid, gid))?;
                }
            }
        }
        run_stage_commands(
            &stage_root,
            &stage.run[copy_from_after_run_index..],
            &stage_environment(base_info, &stage.env),
            workdir,
            stage.user.as_deref(),
            &runtime_dir
                .join("build")
                .join("cache")
                .join(format!("stage-{idx}")),
            secrets,
            context_dir,
            control,
            execution_options,
        )?;
        // Parallel build attempts share the runtime directory. Allocate the
        // streamed layer's scratch file too, rather than using a fixed name.
        let layer_dir = create_build_dir(runtime_dir, &format!("stage-layer-{idx}"))?;
        let layer_temp = layer_dir.join("layer");
        layer_media_type = build_layer_from_snapshot_to_file(
            &stage_root,
            &stage_baseline,
            compression,
            &layer_temp,
            execution_options.source_date_epoch,
        )?;
        let (digest, size) = write_blob_from_file(runtime_dir, &layer_temp)?;
        let _ = fs::remove_dir_all(layer_dir);
        layer_digest = digest;
        layer_size = size as i64;
    }

    Ok(BuiltStage {
        root: stage_root,
        name: stage.name.clone(),
        layer_digest,
        layer_media_type,
        layer_size,
        context_layer,
    })
}

fn resolve_copy_destination(workdir: Option<&str>, destination: &str) -> String {
    if destination.starts_with('/') {
        return destination.to_string();
    }
    let base = workdir.unwrap_or("/").trim_end_matches('/');
    // Keep the directory intent of Docker's `./` spelling.  `Path` would
    // normalize `/app/./` before `copy_from_context` can see its trailing
    // slash, causing a multi-source COPY to treat `/app` as a file target.
    if destination == "." || destination == "./" {
        return if base.is_empty() || base == "/" {
            "/".to_string()
        } else {
            format!("{base}/")
        };
    }
    if base.is_empty() || base == "/" {
        format!("/{destination}")
    } else {
        format!("{base}/{destination}")
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_from_dockerfile_with_store_and_compression_with_contexts_and_secrets(
    dockerfile_path: &Path,
    tag: Option<&str>,
    runtime_dir: &Path,
    compression: CompressionFormat,
    store: &LocalImageStore,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
    named_contexts: &HashMap<String, PathBuf>,
    secrets: &HashMap<String, PathBuf>,
    authorization_plan_digest: Option<&str>,
) -> Result<BuildResult, DockerfileBuildError> {
    build_from_dockerfile_with_store_and_compression_with_contexts_and_secrets_and_build_args(
        dockerfile_path,
        tag,
        runtime_dir,
        compression,
        store,
        authority,
        named_contexts,
        secrets,
        authorization_plan_digest,
        &HashMap::new(),
        &DockerfileExecutionOptions::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_from_dockerfile_with_store_and_compression_with_contexts_and_secrets_and_build_args(
    dockerfile_path: &Path,
    tag: Option<&str>,
    runtime_dir: &Path,
    compression: CompressionFormat,
    store: &LocalImageStore,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
    named_contexts: &HashMap<String, PathBuf>,
    secrets: &HashMap<String, PathBuf>,
    authorization_plan_digest: Option<&str>,
    build_args: &HashMap<String, String>,
    execution_options: &DockerfileExecutionOptions,
) -> Result<BuildResult, DockerfileBuildError> {
    if !dockerfile_path.exists() {
        return Err(DockerfileBuildError::MissingDockerfile(
            dockerfile_path.display().to_string(),
        ));
    }
    let control = BuildControl::load()?;

    let dockerfile = fs::read_to_string(dockerfile_path)?;
    let stages = parse_stages_with_build_args(&dockerfile, build_args)?;
    let context_dir = dockerfile_path
        .parent()
        .ok_or_else(|| DockerfileBuildError::Invalid("invalid dockerfile path".to_string()))?;
    let context_hash = build_context_binding_digest(
        &hash_context_dir_excluding(context_dir, dockerfile_path, Some(runtime_dir))?,
        named_contexts,
    )?;
    let named_contexts = canonicalize_named_contexts(named_contexts)?;
    let dockerfile_digest = hex::encode(Sha256::digest(dockerfile.as_bytes()));
    let aliases = earlier_stage_aliases(&stages)?;
    let mut base_infos = Vec::new();
    for (index, stage) in stages.iter().enumerate() {
        let base_info = if aliases[index].contains_key(&stage.base.to_ascii_lowercase()) {
            BaseImageInfo {
                layers: Vec::new(),
                descriptors: Vec::new(),
                digest: None,
                onbuild: Vec::new(),
                env: Vec::new(),
                config: BaseConfig::default(),
            }
        } else {
            resolve_base_image(store, runtime_dir, &stage.base, authority)?
        };
        base_infos.push(base_info);
    }
    let mut stages = stages;
    for (stage, base_info) in stages.iter_mut().zip(&base_infos) {
        apply_onbuild_triggers(stage, &base_info.onbuild)?;
    }
    if let Some(max_steps) = control.limits.max_steps {
        let total_steps: usize = stages.iter().map(|stage| stage.run.len()).sum();
        if total_steps as u64 > max_steps {
            return Err(DockerfileBuildError::LimitExceeded(format!(
                "Dockerfile declares {total_steps} RUN steps; limit is {max_steps}"
            )));
        }
    }
    let cache_platform = output_platform_for_config(
        execution_options.target_platform.as_deref(),
        &base_infos
            .last()
            .ok_or_else(|| DockerfileBuildError::Invalid("missing final stage".to_string()))?
            .config,
    )?
    .formatted;
    let cache_key = build_cache_key_with_build_args(
        &dockerfile,
        compression,
        &context_hash,
        &base_infos,
        &cache_platform,
        build_args,
    );
    let base_digests = base_infos
        .iter()
        .map(|info| info.digest.clone().unwrap_or_else(|| "scratch".to_string()))
        .collect::<Vec<_>>();
    let mut journal = match load_build_journal(runtime_dir)? {
        Some(existing)
            if existing.identity_matches(
                &cache_key,
                &context_hash,
                &dockerfile_digest,
                &base_digests,
            ) =>
        {
            // Same build identity: keep the completed-stage record so an
            // interrupted build resumes from the stages the journal says
            // finished. Stage checkpoints stay authoritative per stage: a
            // checkpoint restores only when its content-addressed stage
            // identity still matches.
            existing
        }
        _ => {
            // No journal, or the source/context/base identity changed since
            // the journaled build: start a fresh progress record. Stage
            // checkpoints are kept, not discarded — each is bound to the
            // content-addressed identity of its stage, so an edited
            // Dockerfile still reuses the checkpoints of the stages whose
            // inputs did not change and overwrites only the rest.
            BuildJournal {
                cache_key: cache_key.clone(),
                context_digest: context_hash.clone(),
                dockerfile_digest: dockerfile_digest.clone(),
                base_digests: base_digests.clone(),
                image_reference: String::new(),
                authorization_plan_digest: None,
                state: BuildJournalState::Running,
                completed_stages: Vec::new(),
                failure_output: None,
            }
        }
    };
    journal.state = BuildJournalState::Running;
    journal.authorization_plan_digest = authorization_plan_digest.map(str::to_string);
    journal.image_reference = canonicalize_reference(tag.unwrap_or("local/build:latest"))?;
    // Checked before the cache path so a cancelled build never re-publishes a
    // cached reference. The journal itself is written only when stages will
    // actually execute: a cache hit must not create build directories, and a
    // cancelled or failing build is journaled by the outcome paths below.
    let mut journaled_attempt = false;
    let outcome = control.check("build start").and_then(|()| {
        let mut cache = load_build_cache(runtime_dir)?;
        if execution_options.no_cache.is_none() && !has_sensitive_mounts(&stages) {
            if let Some(entry) = cache.get(&cache_key).cloned() {
                if !entry.cache_key.is_empty() && entry.cache_key != cache_key {
                    return Err(DockerfileBuildError::Invalid(
                        "build cache provenance key mismatch".to_string(),
                    ));
                }
                if (!entry.context_digest.is_empty() && entry.context_digest != context_hash)
                    || (!entry.dockerfile_digest.is_empty()
                        && entry.dockerfile_digest != dockerfile_digest)
                    || (!entry.base_digests.is_empty() && entry.base_digests != base_digests)
                {
                    return Err(DockerfileBuildError::Invalid(
                        "build cache source provenance mismatch".to_string(),
                    ));
                }
                let layer_path = layer_blob_path(runtime_dir, &entry.layer_digest);
                let config_path = config_path(runtime_dir, &entry.config_digest);
                let layer_valid = entry.layer_size >= 0
                    && fs::metadata(&layer_path)
                        .is_ok_and(|metadata| metadata.len() == entry.layer_size as u64)
                    && file_matches_digest(&layer_path, &entry.layer_digest);
                let config_valid = file_matches_digest(&config_path, &entry.config_digest);
                if layer_valid && config_valid {
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
        }
        // Stages will execute: record the attempt now so interrupted builds
        // are resumable. This is the first write that creates the build dir.
        save_build_journal(runtime_dir, &journal)?;
        journaled_attempt = true;
        execute_stages_and_publish(
            &stages,
            &base_infos,
            runtime_dir,
            context_dir,
            dockerfile_path,
            compression,
            store,
            authority,
            tag,
            &named_contexts,
            secrets,
            &mut cache,
            &cache_key,
            &context_hash,
            &dockerfile_digest,
            &base_digests,
            &control,
            &mut journal,
            execution_options,
        )
    });
    match outcome {
        Ok(result) => {
            // A pure cache hit never created the build dir; leave no journal
            // behind either so the no-rebuild invariant holds on disk.
            if journaled_attempt {
                journal.state = BuildJournalState::Complete;
                save_build_journal(runtime_dir, &journal)?;
            }
            Ok(result)
        }
        Err(error) => {
            journal.state = if matches!(error, DockerfileBuildError::Cancelled(_)) {
                BuildJournalState::Cancelled
            } else {
                BuildJournalState::Failed
            };
            journal.failure_output = Some(error.to_string());
            // The journal is best-effort on the failure path; the build error
            // is the authoritative outcome and must not be masked.
            let _ = save_build_journal(runtime_dir, &journal);
            Err(error)
        }
    }
}

/// Append one stage lifecycle event to the trace file named by
/// FERROCRATE_BUILD_STAGE_TRACE. Events: `start <idx> <unix_ns>` before a
/// stage executes, `end <idx> <unix_ns> ok|err` after, and
/// `restore <idx> <unix_ns>` when a stage is restored from its checkpoint.
/// The trace is build instrumentation: it never gates build behavior.
fn stage_trace_event(kind: &str, idx: usize, detail: &str) {
    let Some(path) = std::env::var_os("FERROCRATE_BUILD_STAGE_TRACE") else {
        return;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let line = format!("{kind} {idx} {now} {detail}\n");
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = file.write_all(line.as_bytes());
    }
}

/// Run every stage of one dependency batch over a bounded worker pool.
/// At most `max_workers` stages execute concurrently; the rest queue. Each
/// worker re-checks build control before starting a stage so cancellation and
/// limits stop queued stages immediately. Results are delivered to
/// `on_result` on the coordinating thread as they arrive, so callers can
/// journal each stage atomically while the rest of the batch still runs.
/// Returns the number of results delivered; a panicked worker delivers no
/// result for its stage, so a count below `batch.len()` reports a panic.
fn run_stage_worker_pool<F, T, R>(
    batch: &[usize],
    max_workers: usize,
    control: &BuildControl,
    execute: F,
    mut on_result: R,
) -> usize
where
    F: Fn(usize) -> Result<T, DockerfileBuildError> + Send + Sync,
    R: FnMut(usize, Result<T, DockerfileBuildError>) + Send,
    T: Send,
{
    let worker_count = batch.len().min(max_workers.max(1));
    let queue = Mutex::new(VecDeque::from_iter(batch.iter().copied()));
    let (sender, receiver) = mpsc::channel::<(usize, Result<T, DockerfileBuildError>)>();
    let mut delivered = 0usize;
    thread::scope(|scope| {
        let delivered = &mut delivered;
        let coordinator = scope.spawn(move || {
            while *delivered < batch.len() {
                match receiver.recv() {
                    Ok((idx, result)) => {
                        *delivered += 1;
                        on_result(idx, result);
                    }
                    Err(_) => break,
                }
            }
        });
        let queue = &queue;
        let execute = &execute;
        for _ in 0..worker_count {
            let sender = sender.clone();
            scope.spawn(move || loop {
                let next = queue.lock().expect("stage queue").pop_front();
                let Some(idx) = next else {
                    break;
                };
                let result = control.check("stage start").and_then(|()| execute(idx));
                if sender.send((idx, result)).is_err() {
                    break;
                }
            });
        }
        drop(sender);
        let _ = coordinator.join();
    });
    delivered
}

#[allow(clippy::too_many_arguments)]
fn execute_stages_and_publish(
    stages: &[StageSpec],
    base_infos: &[BaseImageInfo],
    runtime_dir: &Path,
    context_dir: &Path,
    dockerfile_path: &Path,
    compression: CompressionFormat,
    store: &LocalImageStore,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
    tag: Option<&str>,
    named_contexts: &HashMap<String, PathBuf>,
    secrets: &HashMap<String, PathBuf>,
    cache: &mut HashMap<String, BuildCacheEntry>,
    cache_key: &str,
    context_hash: &str,
    dockerfile_digest: &str,
    base_digests: &[String],
    control: &BuildControl,
    journal: &mut BuildJournal,
    execution_options: &DockerfileExecutionOptions,
) -> Result<BuildResult, DockerfileBuildError> {
    let mut stage_roots = vec![None; stages.len()];
    let mut stage_names: HashMap<String, PathBuf> = HashMap::new();
    let ignore_patterns = load_dockerignore_patterns(context_dir)?;
    let checkpointing = !has_sensitive_mounts(stages);
    let mut checkpoints = if checkpointing {
        load_stage_checkpoints(runtime_dir)?
    } else {
        HashMap::new()
    };

    let dependency_graph = build_stage_dependency_graph(stages, named_contexts)?;
    let batches = build_stage_execution_batches(&dependency_graph)?;
    let mut stage_workdirs: Vec<Option<String>> = Vec::with_capacity(stages.len());
    for (idx, stage) in stages.iter().enumerate() {
        let inherited = stages[..idx]
            .iter()
            .enumerate()
            .find(|(_, candidate)| {
                candidate
                    .name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&stage.base))
            })
            .and_then(|(parent, _)| stage_workdirs[parent].clone());
        stage_workdirs.push(
            stage
                .workdir
                .clone()
                .or(inherited)
                .or_else(|| base_infos[idx].config.workdir.clone()),
        );
    }
    let stage_identities = stage_content_identities(
        stages,
        base_digests,
        context_hash,
        &dependency_graph,
        compression,
    )?;
    let mut built: Vec<Option<BuiltStage>> = (0..stages.len()).map(|_| None).collect();
    let max_workers = resolve_max_parallel_stages(&control.limits);
    for batch in batches {
        control.check("stage batch start")?;
        let roots_snapshot = stage_roots
            .iter()
            .map(|root| {
                root.clone()
                    .unwrap_or_else(|| runtime_dir.join("build").join("unbuilt-stage"))
            })
            .collect::<Vec<_>>();
        let names_snapshot = stage_names.clone();
        // Each stage has an isolated rootfs and stage-scoped RUN cache. The
        // unique build-directory allocator and content-addressed blob writer
        // make independent stages safe to execute concurrently; the worker
        // pool bounds how many do at once. A stage resumes from its
        // checkpoint when the checkpoint was produced by the same
        // content-addressed stage identity.
        let worker_checkpoints = checkpoints.clone();
        let execute_stage = |idx: usize| -> Result<BuiltStage, DockerfileBuildError> {
            let inherited_root = resolve_stage_root(
                &roots_snapshot,
                &names_snapshot,
                &HashMap::new(),
                &stages[idx].base,
            );
            let checkpoint = worker_checkpoints
                .get(&idx)
                .filter(|_| !stage_ignores_cache(&stages[idx], execution_options))
                .filter(|checkpoint| checkpoint.build_key == stage_identities[idx])
                .cloned();
            let outcome = match checkpoint {
                Some(checkpoint) => {
                    match restore_stage_from_checkpoint(
                        runtime_dir,
                        idx,
                        &base_infos[idx],
                        inherited_root.as_deref(),
                        &checkpoint,
                    ) {
                        Ok(Some(mut output)) => {
                            stage_trace_event("restore", idx, "");
                            output.name = stages[idx].name.clone();
                            Ok(output)
                        }
                        Ok(None) => build_one_stage(
                            idx,
                            &stages[idx],
                            &base_infos[idx],
                            runtime_dir,
                            context_dir,
                            dockerfile_path,
                            compression,
                            &ignore_patterns,
                            named_contexts,
                            secrets,
                            &roots_snapshot,
                            &names_snapshot,
                            inherited_root.as_deref(),
                            stage_workdirs[idx].as_deref(),
                            control,
                            execution_options,
                        ),
                        Err(error) => Err(error),
                    }
                }
                None => build_one_stage(
                    idx,
                    &stages[idx],
                    &base_infos[idx],
                    runtime_dir,
                    context_dir,
                    dockerfile_path,
                    compression,
                    &ignore_patterns,
                    named_contexts,
                    secrets,
                    &roots_snapshot,
                    &names_snapshot,
                    inherited_root.as_deref(),
                    stage_workdirs[idx].as_deref(),
                    control,
                    execution_options,
                ),
            };
            match &outcome {
                Ok(_) => stage_trace_event("end", idx, "ok"),
                Err(_) => stage_trace_event("end", idx, "err"),
            }
            outcome
        };
        // The trace `start` event belongs inside the worker so recorded
        // intervals reflect actual pool concurrency.
        let traced_execute = |idx: usize| -> Result<BuiltStage, DockerfileBuildError> {
            stage_trace_event("start", idx, "");
            execute_stage(idx)
        };
        let mut completed_in_batch = 0usize;
        let mut batch_error: Option<DockerfileBuildError> = None;
        let mut journal_error: Option<DockerfileBuildError> = None;
        let delivered = run_stage_worker_pool(
            &batch,
            max_workers,
            control,
            traced_execute,
            |idx, result| match result {
                Ok(output) => {
                    if checkpointing {
                        checkpoints.insert(
                            idx,
                            StageCheckpoint {
                                build_key: stage_identities[idx].clone(),
                                layer_digest: output.layer_digest.clone(),
                                layer_media_type: output.layer_media_type.clone(),
                                layer_size: output.layer_size,
                                context_layer: output.context_layer.clone(),
                            },
                        );
                    }
                    stage_roots[idx] = Some(output.root.clone());
                    if let Some(name) = output.name.as_ref() {
                        stage_names.insert(name.clone(), output.root.clone());
                    }
                    journal.completed_stages.push(idx);
                    journal.completed_stages.sort_unstable();
                    journal.completed_stages.dedup();
                    // Journal and checkpoints are written once per completed
                    // stage while the rest of the batch still runs, so an
                    // interrupted parallel batch keeps the stages that did
                    // finish resumable.
                    if checkpointing {
                        if let Err(error) = save_stage_checkpoints(runtime_dir, &checkpoints) {
                            journal_error.get_or_insert(error);
                        }
                    }
                    if let Err(error) = save_build_journal(runtime_dir, journal) {
                        journal_error.get_or_insert(error);
                    }
                    built[idx] = Some(output);
                    completed_in_batch += 1;
                }
                Err(error) => {
                    batch_error.get_or_insert(error);
                }
            },
        );
        if delivered != batch.len() {
            return Err(DockerfileBuildError::Invalid(
                "parallel stage worker panicked".to_string(),
            ));
        }
        if let Some(error) = journal_error {
            return Err(error);
        }
        if let Some(error) = batch_error {
            return Err(error);
        }
        // Every stage of the batch delivered an Ok result, so `built` and
        // `stage_roots` now hold an entry for each index.
        debug_assert_eq!(completed_in_batch, batch.len());
    }

    let final_idx = stages
        .len()
        .checked_sub(1)
        .ok_or_else(|| DockerfileBuildError::Invalid("no stages built".to_string()))?;
    let final_stage = &stages[final_idx];
    let stage_layer_digests = built
        .iter()
        .map(|output| {
            output
                .as_ref()
                .map(|stage| stage.layer_digest.clone())
                .ok_or_else(|| {
                    DockerfileBuildError::Invalid("stage provenance missing".to_string())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let final_output = built[final_idx]
        .take()
        .ok_or_else(|| DockerfileBuildError::Invalid("final stage was not built".to_string()))?;
    // S24: what the Dockerfile does not set, the image inherits from its base.
    // The environment is composed the same way the RUN steps already compose it,
    // so the built image carries the base's PATH.
    let final_base = &base_infos[final_idx].config;
    let final_env = stage_environment(&base_infos[final_idx], &final_stage.env);
    let mut final_labels = final_base.labels.clone();
    final_labels.extend(
        final_stage
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    let (entrypoint, cmd) = inherited_command(
        final_stage.entrypoint.as_deref(),
        final_stage.cmd.as_deref(),
        final_base.entrypoint.as_deref(),
        final_base.cmd.as_deref(),
    );
    let exposed_ports = merge_unique(&final_base.exposed_ports, &final_stage.exposed_ports);
    let volumes = merge_unique(&final_base.volumes, &final_stage.volumes);
    let output_platform = output_platform_for_config(
        execution_options.target_platform.as_deref(),
        final_base,
    )?;
    let config_json = build_config_json(
        &output_platform,
        execution_options.source_date_epoch,
        final_stage.healthcheck.clone(),
        &final_env,
        &final_labels,
        final_stage
            .workdir
            .as_deref()
            .or(final_base.workdir.as_deref()),
        final_stage.user.as_deref().or(final_base.user.as_deref()),
        entrypoint,
        cmd,
        final_stage
            .stop_signal
            .as_deref()
            .or(final_base.stop_signal.as_deref()),
        final_stage.author.as_deref(),
        &final_stage.onbuild,
        &exposed_ports,
        &volumes,
    );
    let config_bytes = config_json.as_bytes();
    let config_digest = sha256_digest_bytes(config_bytes);
    let mut layers = base_infos[final_idx].descriptors.clone();
    if let Some(context_layer) = &final_output.context_layer {
        layers.push(Descriptor {
            media_type: context_layer.media_type.clone(),
            digest: context_layer.digest.clone(),
            size: context_layer.size,
            urls: Vec::new(),
            annotations: None,
            artifact_type: None,
            platform: None,
        });
    }
    layers.push(Descriptor {
        media_type: final_output.layer_media_type.clone(),
        digest: final_output.layer_digest.clone(),
        size: final_output.layer_size,
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
    let manifest_json =
        serde_json::to_string(&manifest).map_err(|err| io::Error::other(err.to_string()))?;
    let reference = canonicalize_reference(tag.unwrap_or("local/build:latest"))?;
    // A build cancelled while its layers were being assembled must never
    // publish the resulting image reference.
    control.check("image publish")?;
    store.put_reference(
        authority,
        &reference,
        &config_digest,
        OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        &manifest_json,
    )?;
    write_config(runtime_dir, &config_digest, config_bytes)?;
    if !has_sensitive_mounts(stages) {
        cache.insert(
            cache_key.to_string(),
            BuildCacheEntry {
                cache_key: cache_key.to_string(),
                created_at_unix: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                context_digest: context_hash.to_string(),
                dockerfile_digest: dockerfile_digest.to_string(),
                base_digests: base_digests.to_vec(),
                stage_layer_digests,
                layer_digest: final_output.layer_digest.clone(),
                layer_size: final_output.layer_size,
                layer_media_type: final_output.layer_media_type,
                config_digest: config_digest.clone(),
                config_json: config_json.clone(),
                manifest_json: manifest_json.clone(),
            },
        );
        save_build_cache(runtime_dir, cache)?;
    }
    Ok(BuildResult {
        reference,
        layer_digest: final_output.layer_digest,
        config_digest,
    })
}

fn stage_ignores_cache(stage: &StageSpec, options: &DockerfileExecutionOptions) -> bool {
    let Some(names) = options.no_cache.as_ref() else {
        return false;
    };
    names.is_empty()
        || stage
            .name
            .as_deref()
            .is_some_and(|name| names.iter().any(|item| item.eq_ignore_ascii_case(name)))
}

pub fn execute_dockerfile_build_authorized(
    plan: ImageBuildPlan,
    store: &LocalImageStore,
    permit: crate::authorization::surface::SurfacePermit,
) -> Result<BuildResult, DockerfileBuildError> {
    execute_dockerfile_build_authorized_with_secrets(plan, store, permit, &HashMap::new())
}

pub fn execute_dockerfile_build_authorized_with_secrets(
    plan: ImageBuildPlan,
    store: &LocalImageStore,
    permit: crate::authorization::surface::SurfacePermit,
    secrets: &HashMap<String, PathBuf>,
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
    let observed = prepare_dockerfile_build_with_contexts_and_build_args_and_options(
        &plan.dockerfile_path,
        Some(&plan.canonical_tag),
        &plan.runtime_dir,
        plan.compression,
        store,
        &plan.named_contexts,
        &plan.build_args,
        &plan.execution_options,
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
    let authorization_plan_digest = hex::encode(plan.plan_digest());
    match build_from_dockerfile_with_store_and_compression_with_contexts_and_secrets_and_build_args(
        &plan.dockerfile_path,
        Some(&plan.canonical_tag),
        &plan.runtime_dir,
        plan.compression,
        store,
        &authority,
        &plan.named_contexts,
        secrets,
        Some(&authorization_plan_digest),
        &plan.build_args,
        &plan.execution_options,
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
    source_date_epoch: Option<u64>,
) -> Result<(Vec<u8>, String), DockerfileBuildError> {
    let mut tar_builder = Builder::new(Vec::new());
    add_directory(
        &mut tar_builder,
        source_dir,
        source_dir,
        dockerfile_path,
        source_date_epoch,
    )?;
    let tar_bytes = tar_builder
        .into_inner()
        .map_err(|err| io::Error::other(err.to_string()))?;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagePathState {
    size: u64,
    modified: Option<SystemTime>,
    mode: u32,
    kind: StagePathKind,
    symlink_target: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StagePathKind {
    File,
    Directory,
    Symlink,
    Other,
}

fn snapshot_stage_root(
    root: &Path,
) -> Result<BTreeMap<PathBuf, StagePathState>, DockerfileBuildError> {
    fn visit(
        root: &Path,
        path: &Path,
        entries: &mut BTreeMap<PathBuf, StagePathState>,
    ) -> io::Result<()> {
        let mut children = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        children.sort_by_key(|entry| entry.path());
        for child in children {
            let path = child.path();
            let metadata = fs::symlink_metadata(&path)?;
            let file_type = metadata.file_type();
            let kind = if file_type.is_file() {
                StagePathKind::File
            } else if file_type.is_dir() {
                StagePathKind::Directory
            } else if file_type.is_symlink() {
                StagePathKind::Symlink
            } else {
                StagePathKind::Other
            };
            let relative = path
                .strip_prefix(root)
                .expect("stage entry under root")
                .to_path_buf();
            entries.insert(
                relative,
                StagePathState {
                    size: metadata.len(),
                    modified: metadata.modified().ok(),
                    #[cfg(unix)]
                    mode: metadata.permissions().mode(),
                    #[cfg(not(unix))]
                    mode: 0,
                    kind,
                    symlink_target: if file_type.is_symlink() {
                        Some(fs::read_link(&path)?)
                    } else {
                        None
                    },
                },
            );
            if file_type.is_dir() {
                visit(root, &path, entries)?;
            }
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries)?;
    Ok(entries)
}

fn build_layer_from_snapshot_to_file(
    root: &Path,
    before: &BTreeMap<PathBuf, StagePathState>,
    compression: CompressionFormat,
    output: &Path,
    source_date_epoch: Option<u64>,
) -> Result<String, DockerfileBuildError> {
    let after = snapshot_stage_root(root)?;
    let file = File::create(output)?;
    let writer: Box<dyn Write> = match compression {
        CompressionFormat::Gzip => Box::new(GzEncoder::new(file, Compression::default())),
        CompressionFormat::Zstd => Box::new(
            zstd::stream::write::Encoder::new(file, 0)
                .map_err(|err| io::Error::other(err.to_string()))?
                .auto_finish(),
        ),
        CompressionFormat::None => {
            return Err(DockerfileBuildError::Unsupported(
                "uncompressed layers are not supported".to_string(),
            ))
        }
    };
    let mut builder = Builder::new(writer);
    // A whiteout is a zero-length regular file next to the removed name.
    // Whiteouting a directory removes its descendants too. Emitting child
    // whiteouts after the directory has gone could recreate that directory
    // while a runtime applies the layer, so retain only top-level deletions.
    for path in before.keys().filter(|path| {
        !after.contains_key(*path)
            && !before.keys().any(|ancestor| {
                ancestor != *path && path.starts_with(ancestor) && !after.contains_key(ancestor)
            })
    }) {
        append_whiteout(&mut builder, path)?;
    }
    for (path, state) in &after {
        if before.get(path) == Some(state) {
            continue;
        }
        if before.get(path).is_some_and(|old| old.kind != state.kind) {
            append_whiteout(&mut builder, path)?;
        }
        append_stage_path(&mut builder, root, path, state, source_date_epoch)?;
    }
    builder
        .into_inner()
        .map_err(|err| io::Error::other(err.to_string()))?
        .flush()?;
    match compression {
        CompressionFormat::Gzip => Ok(OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string()),
        CompressionFormat::Zstd => Ok(OCI_IMAGE_LAYER_ZSTD_MEDIA_TYPE.to_string()),
        CompressionFormat::None => unreachable!(),
    }
}

fn append_whiteout<W: Write>(
    builder: &mut Builder<W>,
    path: &Path,
) -> Result<(), DockerfileBuildError> {
    let name = path
        .file_name()
        .ok_or_else(|| DockerfileBuildError::Invalid("cannot whiteout stage root".to_string()))?;
    let whiteout = path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(format!(".wh.{}", name.to_string_lossy()));
    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_mode(0);
    header.set_mtime(0);
    header.set_cksum();
    builder
        .append_data(&mut header, whiteout, io::empty())
        .map_err(DockerfileBuildError::Io)
}

fn append_stage_path<W: Write>(
    builder: &mut Builder<W>,
    root: &Path,
    relative: &Path,
    state: &StagePathState,
    source_date_epoch: Option<u64>,
) -> Result<(), DockerfileBuildError> {
    let path = root.join(relative);
    match state.kind {
        StagePathKind::File => append_tar_file(builder, &path, relative, source_date_epoch)
            .map_err(DockerfileBuildError::Io),
        StagePathKind::Directory => {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(state.mode);
            header.set_mtime(0);
            header.set_cksum();
            builder
                .append_data(&mut header, relative, io::empty())
                .map_err(DockerfileBuildError::Io)
        }
        StagePathKind::Symlink => append_tar_symlink_entry(
            builder,
            relative,
            state
                .symlink_target
                .as_deref()
                .unwrap_or_else(|| Path::new("")),
        )
        .map_err(DockerfileBuildError::Io),
        StagePathKind::Other => Ok(()),
    }
}

/// Layers previously listed only regular files, so directories without any
/// file inside and symlinks vanished from every generated layer. Explicit
/// headers keep both alive across the tar round-trip.
fn append_tar_dir_entry<W: Write>(
    builder: &mut Builder<W>,
    relative: &Path,
) -> std::io::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o755);
    header.set_mtime(0);
    builder.append_data(&mut header, relative, std::io::empty())
}

/// Preserve the link verbatim; relative, absolute and dangling targets all
/// survive instead of being dereferenced or silently dropped.
fn append_tar_symlink_entry<W: Write>(
    builder: &mut Builder<W>,
    relative: &Path,
    target: &Path,
) -> std::io::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    header.set_mtime(0);
    builder.append_link(&mut header, relative, target)
}

fn add_directory(
    builder: &mut Builder<Vec<u8>>,
    base: &Path,
    path: &Path,
    dockerfile_path: Option<&Path>,
    source_date_epoch: Option<u64>,
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
            append_tar_dir_entry(builder, &relative).map_err(DockerfileBuildError::Io)?;
            add_directory(
                builder,
                base,
                &entry_path,
                dockerfile_path,
                source_date_epoch,
            )?;
        } else if file_type.is_symlink() {
            let target = fs::read_link(&entry_path)?;
            append_tar_symlink_entry(builder, &relative, &target)
                .map_err(DockerfileBuildError::Io)?;
        } else if file_type.is_file() {
            append_tar_file(builder, &entry_path, &relative, source_date_epoch)
                .map_err(DockerfileBuildError::Io)?;
        }
    }
    Ok(())
}

fn append_tar_file<W: Write>(
    builder: &mut Builder<W>,
    source: &Path,
    archive_path: &Path,
    source_date_epoch: Option<u64>,
) -> io::Result<()> {
    let metadata = fs::metadata(source)?;
    let mut header = tar::Header::new_gnu();
    header.set_metadata(&metadata);
    if let Some(epoch) = source_date_epoch {
        let modified = metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map(|value| value.as_secs())
            .unwrap_or_default();
        header.set_mtime(modified.min(epoch));
    }
    header.set_cksum();
    builder.append_data(&mut header, archive_path, File::open(source)?)
}

#[allow(clippy::too_many_arguments)]
fn build_config_json(
    platform: &BuildkitPlatform,
    source_date_epoch: Option<u64>,
    healthcheck: Option<HealthcheckSpec>,
    env: &[String],
    labels: &HashMap<String, String>,
    workdir: Option<&str>,
    user: Option<&str>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    stop_signal: Option<&str>,
    author: Option<&str>,
    onbuild: &[String],
    exposed_ports: &[String],
    volumes: &[String],
) -> String {
    let created = source_date_epoch
        .and_then(|epoch| chrono::DateTime::from_timestamp(epoch as i64, 0))
        .map(|timestamp| timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());
    let health = healthcheck.map(|spec| {
        json!({
            "Test": spec.test,
            "Interval": spec.interval_nanos,
            "Timeout": spec.timeout_nanos,
            "Retries": spec.retries,
            "StartPeriod": spec.start_period_nanos,
            "StartInterval": spec.start_interval_nanos
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
        "created": created,
        "author": author,
        "architecture": platform.architecture,
        "os": platform.os,
        "os.version": if platform.os_version.is_empty() {
            None
        } else {
            Some(platform.os_version.as_str())
        },
        "variant": if platform.variant.is_empty() {
            None
        } else {
            Some(platform.variant.as_str())
        },
        "config": {
            "Env": env,
            "Cmd": cmd,
            "Entrypoint": entrypoint,
            "WorkingDir": workdir,
            "User": user,
            "Labels": labels,
            "Healthcheck": health,
            "StopSignal": stop_signal,
            "OnBuild": if onbuild.is_empty() {
                None
            } else {
                Some(onbuild)
            },
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

/// Install an already-streamed layer without ever materialising it in memory.
/// The layer blob is the authoritative copy; unlike small config blobs it is
/// deliberately not duplicated in the byte-addressed CAS.
fn write_blob_from_file(
    runtime_dir: &Path,
    source: &Path,
) -> Result<(String, u64), DockerfileBuildError> {
    let mut input = File::open(source)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes += read as u64;
    }
    let digest = format!("sha256:{:x}", hasher.finalize());
    let target = layer_blob_path(runtime_dir, &digest);
    if !target.exists() {
        fs::create_dir_all(target.parent().expect("layer blob parent"))?;
        fs::copy(source, &target)?;
    }
    Ok((digest, bytes))
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
    let temporary = path.with_extension(format!(
        "json.tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(temporary, &path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn validate_imported_cache_entry(
    key: &str,
    entry: &BuildCacheEntry,
) -> Result<(), DockerfileBuildError> {
    let valid_hex_digest = |value: &str| {
        let Some(hex) = value.strip_prefix("sha256:") else {
            return false;
        };
        hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    };
    if key.len() != 64
        || !key.bytes().all(|byte| byte.is_ascii_hexdigit())
        || entry.cache_key != key
        || !valid_hex_digest(&entry.layer_digest)
        || !valid_hex_digest(&entry.config_digest)
        || entry.stage_layer_digests.is_empty()
        || entry
            .stage_layer_digests
            .iter()
            .any(|digest| !valid_hex_digest(digest))
        || entry.layer_size < 0
        || entry.layer_media_type.is_empty()
        || serde_json::from_str::<serde_json::Value>(&entry.config_json).is_err()
        || serde_json::from_str::<serde_json::Value>(&entry.manifest_json).is_err()
    {
        return Err(DockerfileBuildError::Invalid(
            "imported build cache entry failed provenance validation".to_string(),
        ));
    }
    // The embedded config bytes and manifest must match the digests the
    // entry claims. Without this check an imported entry could publish a
    // reference whose manifest disagrees with its recorded layer identity.
    if sha256_digest_bytes(entry.config_json.as_bytes()) != entry.config_digest {
        return Err(DockerfileBuildError::Invalid(
            "imported build cache config bytes do not match the recorded config digest".to_string(),
        ));
    }
    let manifest = parse_image_manifest(&entry.manifest_json).map_err(|error| {
        DockerfileBuildError::Invalid(format!("imported build cache manifest is invalid: {error}"))
    })?;
    if manifest.config.digest != entry.config_digest
        || manifest
            .layers
            .last()
            .is_none_or(|layer| layer.digest != entry.layer_digest)
    {
        return Err(DockerfileBuildError::Invalid(
            "imported build cache manifest does not bind the recorded config and layer digests"
                .to_string(),
        ));
    }
    Ok(())
}

fn cache_artifacts_path(metadata_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.artifacts", metadata_path.display()))
}

fn copy_cache_artifact(
    source: &Path,
    destination: &Path,
    expected: &str,
) -> Result<(), DockerfileBuildError> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.file_type().is_file() || !file_matches_digest(source, expected) {
        return Err(DockerfileBuildError::Invalid(
            "build cache artifact is not a regular file with the expected digest".to_string(),
        ));
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    if destination.exists() {
        if file_matches_digest(destination, expected) {
            return Ok(());
        }
        return Err(DockerfileBuildError::Invalid(
            "imported build cache artifact conflicts with local artifact".to_string(),
        ));
    }
    let temporary = destination.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::copy(source, &temporary)?;
    let copied = file_matches_digest(&temporary, expected);
    if !copied {
        let _ = fs::remove_file(&temporary);
        return Err(DockerfileBuildError::Invalid(
            "imported build cache artifact failed digest verification".to_string(),
        ));
    }
    fs::rename(temporary, destination)?;
    if let Some(parent) = destination.parent() {
        File::open(parent)?.sync_all()?;
    }
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
    let temporary = destination.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(temporary, destination)?;
    if let Some(parent) = destination.parent() {
        File::open(parent)?.sync_all()?;
    }
    let artifacts = cache_artifacts_path(destination);
    let temporary_artifacts = PathBuf::from(format!(
        "{}.tmp.{}.{}",
        artifacts.display(),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(temporary_artifacts.join("layers"))?;
    fs::create_dir_all(temporary_artifacts.join("configs"))?;
    for entry in cache.values() {
        let layer = layer_blob_path(runtime_dir, &entry.layer_digest);
        if layer.exists() {
            copy_cache_artifact(
                &layer,
                &temporary_artifacts
                    .join("layers")
                    .join(entry.layer_digest.replace(':', "_")),
                &entry.layer_digest,
            )?;
        }
        let config = config_path(runtime_dir, &entry.config_digest);
        if config.exists() {
            copy_cache_artifact(
                &config,
                &temporary_artifacts
                    .join("configs")
                    .join(entry.config_digest.replace(':', "_")),
                &entry.config_digest,
            )?;
        }
    }
    if artifacts.exists() {
        fs::remove_dir_all(&artifacts)?;
    }
    fs::rename(temporary_artifacts, &artifacts)?;
    if let Some(parent) = artifacts.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Import cache metadata, merging entries into the local cache. Malformed
/// metadata fails closed and no partial write is published.
pub fn import_build_cache(
    runtime_dir: &Path,
    source: &Path,
) -> Result<usize, DockerfileBuildError> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.file_type().is_file() {
        return Err(DockerfileBuildError::Invalid(
            "build cache source must be a regular file".to_string(),
        ));
    }
    const MAX_CACHE_IMPORT_BYTES: u64 = 16 * 1024 * 1024;
    if metadata.len() > MAX_CACHE_IMPORT_BYTES {
        return Err(DockerfileBuildError::Invalid(
            "build cache source exceeds the 16 MiB limit".to_string(),
        ));
    }
    let bytes = fs::read(source)?;
    let imported = serde_json::from_slice::<HashMap<String, BuildCacheEntry>>(&bytes)
        .map_err(|error| io::Error::other(error.to_string()))?;
    if imported.len() > 4096 {
        return Err(DockerfileBuildError::Invalid(
            "build cache source contains too many entries".to_string(),
        ));
    }
    for (key, entry) in &imported {
        validate_imported_cache_entry(key, entry)?;
    }
    let mut cache = load_build_cache(runtime_dir)?;
    for (key, entry) in &imported {
        if cache.get(key).is_some_and(|existing| existing != entry) {
            return Err(DockerfileBuildError::Invalid(format!(
                "imported build cache conflicts with local key {key}"
            )));
        }
    }
    let count = imported.len();
    cache.extend(imported);
    save_build_cache(runtime_dir, &cache)?;
    let artifacts = cache_artifacts_path(source);
    if artifacts.exists() {
        let metadata = fs::symlink_metadata(&artifacts)?;
        if !metadata.file_type().is_dir() {
            return Err(DockerfileBuildError::Invalid(
                "build cache artifacts must be a directory".to_string(),
            ));
        }
        for entry in cache.values() {
            let layer_source = artifacts
                .join("layers")
                .join(entry.layer_digest.replace(':', "_"));
            if layer_source.exists() {
                copy_cache_artifact(
                    &layer_source,
                    &layer_blob_path(runtime_dir, &entry.layer_digest),
                    &entry.layer_digest,
                )?;
            }
            let config_source = artifacts
                .join("configs")
                .join(entry.config_digest.replace(':', "_"));
            if config_source.exists() {
                copy_cache_artifact(
                    &config_source,
                    &config_path(runtime_dir, &entry.config_digest),
                    &entry.config_digest,
                )?;
            }
        }
    }
    Ok(count)
}

const REGISTRY_CACHE_KIND_ANNOTATION: &str = "org.ferrocrate.buildcache.kind";

fn registry_cache_reference(value: &str) -> Result<&str, DockerfileBuildError> {
    let reference = value.strip_prefix("registry://").ok_or_else(|| {
        DockerfileBuildError::Invalid(
            "registry cache reference must use the registry:// prefix".to_string(),
        )
    })?;
    crate::registry::parse_image_reference(reference)?;
    Ok(reference)
}

fn registry_cache_descriptor(digest: &str, size: i64, kind: &str) -> Descriptor {
    Descriptor {
        media_type: OCI_IMAGE_LAYER_MEDIA_TYPE.to_string(),
        digest: digest.to_string(),
        size,
        urls: Vec::new(),
        annotations: Some(HashMap::from([(
            REGISTRY_CACHE_KIND_ANNOTATION.to_string(),
            kind.to_string(),
        )])),
        artifact_type: None,
        platform: None,
    }
}

/// Export cache metadata and available layer/config blobs as an OCI registry
/// artifact. The manifest annotations distinguish cache metadata from build
/// artifacts so import can reconstruct a normal local cache sidecar.
pub fn export_build_cache_to_registry(
    runtime_dir: &Path,
    destination: &str,
    auth: Option<&RegistryAuth>,
) -> Result<usize, DockerfileBuildError> {
    let reference = registry_cache_reference(destination)?;
    let cache = load_build_cache(runtime_dir)?;
    let transfer_root = runtime_dir.join("build");
    fs::create_dir_all(&transfer_root)?;
    let transfer = transfer_root.join(format!(
        "registry-cache-{}-{}.json",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    export_build_cache(runtime_dir, &transfer)?;
    let artifacts = cache_artifacts_path(&transfer);
    let client = RegistryClient::new()?;
    let metadata_bytes = fs::read(&transfer)?;
    let metadata_digest = sha256_digest_bytes(&metadata_bytes);
    client.push_blob_from_file(reference, &metadata_digest, &transfer, auth)?;

    let config_bytes =
        br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#;
    let config_path = transfer_root.join(format!(
        "{}.config",
        transfer.file_name().unwrap_or_default().to_string_lossy()
    ));
    fs::write(&config_path, config_bytes)?;
    let config_digest = sha256_digest_bytes(config_bytes);
    client.push_blob_from_file(reference, &config_digest, &config_path, auth)?;

    let mut layers = vec![registry_cache_descriptor(
        &metadata_digest,
        metadata_bytes.len() as i64,
        "metadata",
    )];
    let mut pushed = 1usize;
    let mut seen = HashSet::new();
    for entry in cache.values() {
        for (kind, digest, path) in [
            (
                "layer",
                entry.layer_digest.as_str(),
                artifacts
                    .join("layers")
                    .join(entry.layer_digest.replace(':', "_")),
            ),
            (
                "config",
                entry.config_digest.as_str(),
                artifacts
                    .join("configs")
                    .join(entry.config_digest.replace(':', "_")),
            ),
        ] {
            if !path.exists() || !seen.insert(digest.to_string()) {
                continue;
            }
            if !file_matches_digest(&path, digest) {
                return Err(DockerfileBuildError::Invalid(
                    "local cache artifact failed digest verification before registry export"
                        .to_string(),
                ));
            }
            let size = fs::metadata(&path)?.len() as i64;
            client.push_blob_from_file(reference, digest, &path, auth)?;
            layers.push(registry_cache_descriptor(digest, size, kind));
            pushed += 1;
        }
    }
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_string(),
        config: Descriptor {
            media_type: OCI_IMAGE_CONFIG_MEDIA_TYPE.to_string(),
            digest: config_digest,
            size: config_bytes.len() as i64,
            urls: Vec::new(),
            annotations: None,
            artifact_type: None,
            platform: None,
        },
        layers,
        artifact_type: None,
        subject: None,
        annotations: HashMap::from([(
            "org.ferrocrate.buildcache.version".to_string(),
            "1".to_string(),
        )]),
    };
    let manifest_json = serde_json::to_string(&manifest).map_err(|error| {
        DockerfileBuildError::Invalid(format!("registry cache manifest serialization: {error}"))
    })?;
    client.push_manifest_raw(reference, &manifest_json, auth)?;
    let _ = fs::remove_file(&transfer);
    let _ = fs::remove_file(&config_path);
    let _ = fs::remove_dir_all(&artifacts);
    Ok(pushed)
}

/// Import an OCI registry cache artifact into the local cache and materialize
/// its layer/config blobs for immediate cache-hit validation.
pub fn import_build_cache_from_registry(
    runtime_dir: &Path,
    source: &str,
    auth: Option<&RegistryAuth>,
) -> Result<usize, DockerfileBuildError> {
    let reference = registry_cache_reference(source)?;
    let client = RegistryClient::new()?;
    let manifest = client.pull_manifest(reference, auth)?;
    let metadata = manifest
        .layers
        .iter()
        .find(|descriptor| {
            descriptor
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(REGISTRY_CACHE_KIND_ANNOTATION))
                .is_some_and(|kind| kind == "metadata")
        })
        .ok_or_else(|| {
            DockerfileBuildError::Invalid(
                "registry cache manifest has no metadata layer".to_string(),
            )
        })?;
    let transfer_root = runtime_dir.join("build");
    fs::create_dir_all(&transfer_root)?;
    let transfer = transfer_root.join(format!(
        "registry-cache-import-{}-{}.json",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    client.pull_blob_to_file(reference, &metadata.digest, auth, &transfer)?;
    if !file_matches_digest(&transfer, &metadata.digest) {
        return Err(DockerfileBuildError::Invalid(
            "registry cache metadata failed digest verification".to_string(),
        ));
    }
    let artifacts = cache_artifacts_path(&transfer);
    fs::create_dir_all(artifacts.join("layers"))?;
    fs::create_dir_all(artifacts.join("configs"))?;
    for descriptor in &manifest.layers {
        let kind = descriptor
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(REGISTRY_CACHE_KIND_ANNOTATION));
        let Some(kind @ ("layer" | "config")) = kind.map(String::as_str) else {
            continue;
        };
        let destination = artifacts
            .join(if kind == "layer" { "layers" } else { "configs" })
            .join(descriptor.digest.replace(':', "_"));
        client.pull_blob_to_file(reference, &descriptor.digest, auth, &destination)?;
        if !file_matches_digest(&destination, &descriptor.digest) {
            return Err(DockerfileBuildError::Invalid(
                "registry cache artifact failed digest verification".to_string(),
            ));
        }
    }
    let count = import_build_cache(runtime_dir, &transfer)?;
    let _ = fs::remove_file(&transfer);
    let _ = fs::remove_dir_all(&artifacts);
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
    entries.sort_by(|(left_key, left_time), (right_key, right_time)| {
        left_time
            .cmp(right_time)
            .then_with(|| left_key.cmp(right_key))
    });
    let remove_count = entries.len() - max_entries;
    for (key, _) in entries.into_iter().take(remove_count) {
        cache.remove(&key);
    }
    save_build_cache(runtime_dir, &cache)?;
    Ok(remove_count)
}

/// Native platform fixture used by cache-key unit tests. Production builds
/// bind the normalized frontend target platform selected for their image.
#[cfg(test)]
const BUILD_CACHE_PLATFORM: &str = "linux/amd64";

#[cfg(test)]
fn build_cache_key(
    dockerfile: &str,
    compression: CompressionFormat,
    context_hash: &str,
    base_infos: &[BaseImageInfo],
    platform: &str,
) -> String {
    build_cache_key_with_build_args(
        dockerfile,
        compression,
        context_hash,
        base_infos,
        platform,
        &HashMap::new(),
    )
}

fn build_cache_key_with_build_args(
    dockerfile: &str,
    compression: CompressionFormat,
    context_hash: &str,
    base_infos: &[BaseImageInfo],
    platform: &str,
    build_args: &HashMap<String, String>,
) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"ferrocrate/build-cache/v4\0");
    append_cache_key_field(&mut buf, dockerfile.as_bytes());
    append_cache_key_field(&mut buf, context_hash.as_bytes());
    append_cache_key_field(&mut buf, format!("{compression:?}").as_bytes());
    append_cache_key_field(&mut buf, platform.as_bytes());
    for info in base_infos {
        append_cache_key_field(
            &mut buf,
            info.digest.as_deref().unwrap_or("scratch").as_bytes(),
        );
    }
    for (name, value) in BTreeMap::from_iter(build_args.iter()) {
        append_cache_key_field(&mut buf, name.as_bytes());
        append_cache_key_field(&mut buf, value.as_bytes());
    }
    hex::encode(rvf_crypto::shake256_256(&buf))
}

fn append_cache_key_field(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(&(value.len() as u64).to_be_bytes());
    buffer.extend_from_slice(value);
}

fn hash_context_dir(
    context_dir: &Path,
    dockerfile_path: &Path,
) -> Result<String, DockerfileBuildError> {
    hash_context_dir_excluding(context_dir, dockerfile_path, None)
}

fn hash_context_dir_excluding(
    context_dir: &Path,
    dockerfile_path: &Path,
    excluded_root: Option<&Path>,
) -> Result<String, DockerfileBuildError> {
    let ignore_patterns = load_dockerignore_patterns(context_dir)?;
    let mut files = Vec::new();
    collect_context_files(
        context_dir,
        context_dir,
        dockerfile_path,
        &ignore_patterns,
        excluded_root,
        &mut files,
    )?;
    files.sort();
    let mut buf = Vec::new();
    for rel_path in files {
        let full_path = context_dir.join(&rel_path);
        buf.extend_from_slice(rel_path.to_string_lossy().as_bytes());
        if fs::symlink_metadata(&full_path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            // Hash the link target itself; reading the bytes would fail for
            // dangling links and hide retargets behind the old content.
            buf.extend_from_slice(b"link:");
            buf.extend_from_slice(fs::read_link(&full_path)?.to_string_lossy().as_bytes());
        } else {
            let bytes = fs::read(&full_path)?;
            buf.extend_from_slice(&bytes);
        }
    }
    Ok(hex::encode(rvf_crypto::shake256_256(&buf)))
}

fn canonicalize_named_contexts(
    contexts: &HashMap<String, PathBuf>,
) -> Result<HashMap<String, PathBuf>, DockerfileBuildError> {
    let mut canonical = HashMap::new();
    for (name, path) in contexts {
        if name.is_empty()
            || name.len() > 255
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-/:@".contains(&byte))
        {
            return Err(DockerfileBuildError::Invalid(format!(
                "invalid named build context: {name}"
            )));
        }
        let resolved = fs::canonicalize(path).map_err(|error| {
            DockerfileBuildError::Invalid(format!(
                "named build context {name} is unavailable: {error}"
            ))
        })?;
        if !resolved.is_dir() {
            return Err(DockerfileBuildError::Invalid(format!(
                "named build context {name} must be a directory"
            )));
        }
        canonical.insert(name.clone(), resolved);
    }
    Ok(canonical)
}

fn build_context_binding_digest(
    primary_digest: &str,
    contexts: &HashMap<String, PathBuf>,
) -> Result<String, DockerfileBuildError> {
    let canonical = canonicalize_named_contexts(contexts)?;
    let mut hasher = Sha256::new();
    hasher.update(b"ferrocrate/build-contexts/v1");
    hasher.update(primary_digest.as_bytes());
    let mut names = canonical.keys().collect::<Vec<_>>();
    names.sort();
    for name in names {
        let path = canonical
            .get(name)
            .expect("name came from canonical context map");
        let digest = hash_context_dir(path, &path.join(".ferrocrate-no-dockerfile"))?;
        hasher.update(name.as_bytes());
        hasher.update(digest.as_bytes());
    }
    Ok(hex::encode(hasher.finalize()))
}

fn collect_context_files(
    base: &Path,
    path: &Path,
    dockerfile_path: &Path,
    ignore_patterns: &[String],
    excluded_root: Option<&Path>,
    out: &mut Vec<PathBuf>,
) -> Result<(), DockerfileBuildError> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if excluded_root.is_some_and(|excluded| {
            let resolved_entry =
                fs::canonicalize(&entry_path).unwrap_or_else(|_| entry_path.to_path_buf());
            let resolved_excluded =
                fs::canonicalize(excluded).unwrap_or_else(|_| excluded.to_path_buf());
            resolved_entry == resolved_excluded || resolved_entry.starts_with(&resolved_excluded)
        }) {
            continue;
        }
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
            collect_context_files(
                base,
                &entry_path,
                dockerfile_path,
                ignore_patterns,
                excluded_root,
                out,
            )?;
        } else if file_type.is_file() || file_type.is_symlink() {
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

fn file_matches_digest(path: &Path, expected: &str) -> bool {
    fs::read(path)
        .map(|bytes| sha256_digest_bytes(&bytes) == expected)
        .unwrap_or(false)
}

#[derive(Debug, Clone)]
struct CopyFromSpec {
    from: String,
    srcs: Vec<String>,
    dest: String,
    owner: Option<CopyOwner>,
}

#[derive(Debug, Clone)]
struct CopySpec {
    srcs: Vec<String>,
    dest: String,
    chmod: Option<u32>,
    owner: Option<CopyOwner>,
    checksum: Option<String>,
    parents: bool,
    excludes: Vec<String>,
    extract_archives: bool,
    inline_content: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CopyOwner {
    Numeric(u32, u32),
    Named { user: String, group: Option<String> },
}

#[derive(Debug, Clone)]
struct StageSpec {
    base: String,
    name: Option<String>,
    copy_from: Vec<CopyFromSpec>,
    copy_from_after_run: Vec<CopyFromSpec>,
    copy_from_after_run_index: Option<usize>,
    copy_paths: Vec<CopySpec>,
    healthcheck: Option<HealthcheckSpec>,
    env: Vec<String>,
    args: HashMap<String, String>,
    labels: HashMap<String, String>,
    workdir: Option<String>,
    user: Option<String>,
    stop_signal: Option<String>,
    author: Option<String>,
    onbuild: Vec<String>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    shell: Vec<String>,
    run: Vec<RunSpec>,
    exposed_ports: Vec<String>,
    volumes: Vec<String>,
}

/// Apply Dockerfile parser directives and join line continuations.
///
/// Docker reads `# key=value` directives only from the comment block before
/// the first instruction. `escape` selects the continuation character; any
/// other `key=value` comment stays a comment, matching Docker's
/// warn-and-continue behavior. `syntax` is a leading parser directive, not
/// an image instruction, so the built-in parser consumes it before stages.
fn preprocess_dockerfile(contents: &str) -> Result<String, DockerfileBuildError> {
    let mut escape = '\\';
    let mut lines: Vec<String> = Vec::new();
    let mut in_directive_block = true;
    for raw_line in contents.lines() {
        if in_directive_block {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() {
                lines.push(raw_line.to_string());
                continue;
            }
            if let Some(comment) = trimmed.strip_prefix('#') {
                if let Some((key, value)) = comment.trim().split_once('=') {
                    match key.trim() {
                        "escape" => escape = parse_escape_directive(value.trim())?,
                        "syntax" => {}
                        _ => {}
                    }
                }
                lines.push(raw_line.to_string());
                continue;
            }
            in_directive_block = false;
        }
        lines.push(raw_line.to_string());
    }
    join_continuation_lines(&lines, escape)
}

fn parse_escape_directive(raw: &str) -> Result<char, DockerfileBuildError> {
    let mut chars = raw.chars();
    let escape = chars.next().ok_or_else(|| {
        DockerfileBuildError::Invalid("invalid escape directive: must be ` or \\".to_string())
    })?;
    if chars.next().is_some() || !matches!(escape, '`' | '\\') {
        return Err(DockerfileBuildError::Invalid(
            "invalid escape directive: must be ` or \\".to_string(),
        ));
    }
    Ok(escape)
}

/// Join lines ending with an odd run of the escape character, matching
/// Docker's rule that a doubled escape is a literal character and a single
/// trailing escape continues onto the next line.
fn join_continuation_lines(lines: &[String], escape: char) -> Result<String, DockerfileBuildError> {
    let mut joined: Vec<String> = Vec::new();
    let mut pending: Option<String> = None;
    for line in lines {
        let standalone =
            pending.is_none() && (line.trim().is_empty() || line.trim_start().starts_with('#'));
        if standalone {
            joined.push(line.to_string());
            continue;
        }
        let trailing = line.chars().rev().take_while(|&c| c == escape).count();
        let mut current = pending.take().unwrap_or_default();
        if trailing % 2 == 1 {
            current.push_str(&line[..line.len() - escape.len_utf8()]);
            pending = Some(current);
        } else {
            current.push_str(line);
            joined.push(current);
        }
    }
    if let Some(dangling) = pending {
        return Err(DockerfileBuildError::Invalid(format!(
            "Dockerfile instruction ends with an escape: {dangling}"
        )));
    }
    Ok(joined.join("\n"))
}

fn parse_stages(contents: &str) -> Result<Vec<StageSpec>, DockerfileBuildError> {
    parse_stages_with_build_args(contents, &HashMap::new())
}

fn parse_stages_with_build_args(contents: &str, build_args: &HashMap<String, String>) -> Result<Vec<StageSpec>, DockerfileBuildError> {
    let mut stages = Vec::new();
    let mut current: Option<StageSpec> = None;
    let mut global_args = automatic_platform_args();
    for (name, value) in build_args {
        if global_args.contains_key(name) {
            global_args.insert(name.clone(), value.clone());
        }
    }

    for raw_line in dockerfile_instructions(contents)? {
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
            validate_from_expression(&value, &global_args)?;
            let resolved_from = interpolate_value(&value, &[], &global_args);
            let (base, name) = parse_from(&resolved_from)?;
            current = Some(StageSpec {
                base,
                name,
                copy_from: Vec::new(),
                copy_from_after_run: Vec::new(),
                copy_from_after_run_index: None,
                copy_paths: Vec::new(),
                healthcheck: None,
                env: Vec::new(),
                args: global_args.clone(),
                labels: HashMap::new(),
                workdir: None,
                user: None,
                stop_signal: None,
                author: None,
                onbuild: Vec::new(),
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
            let (name, mut value) = parse_arg(&value)?;
            if let Some(provided) = build_args.get(&name) { value = provided.clone(); }
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
                    if stage.run.is_empty() {
                        stage.copy_from.push(copy);
                    } else {
                        stage.copy_from_after_run_index.get_or_insert(stage.run.len());
                        stage.copy_from_after_run.push(copy);
                    }
                } else if let Some(copy) = parse_copy_spec(&interpolated)? {
                    if copy.checksum.is_some() {
                        return Err(DockerfileBuildError::Invalid(
                            "COPY --checksum is only valid for remote ADD".to_string(),
                        ));
                    }
                    stage.copy_paths.push(copy);
                }
            }
            "ADD" => {
                if let Some(mut copy) = parse_copy_spec(&interpolated)? {
                    copy.extract_archives = true;
                    stage.copy_paths.push(copy);
                }
            }
            "RUN" => {
                let run = parse_run_with_workdir(
                    &interpolated,
                    &stage.shell,
                    stage.workdir.as_deref().unwrap_or("/"),
                )?;
                stage.run.push(run);
            }
            "ARG" => {
                let (name, mut value) = parse_arg(&interpolated)?;
                if let Some(provided) = build_args.get(&name) { value = provided.clone(); }
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
                stage.workdir = Some(resolve_workdir(stage.workdir.as_deref(), &interpolated)?);
            }
            "USER" => {
                stage.user = Some(interpolated.to_string());
            }
            "EXPOSE" => {
                stage
                    .exposed_ports
                    .extend(parse_exposed_ports(&interpolated)?);
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
            "STOPSIGNAL" => {
                stage.stop_signal = Some(parse_stop_signal(&interpolated)?);
            }
            "MAINTAINER" => {
                stage.author = Some(parse_maintainer(&interpolated)?);
            }
            "ONBUILD" => {
                stage.onbuild.push(parse_onbuild(&interpolated)?);
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

fn automatic_platform_args() -> HashMap<String, String> {
    automatic_platform_args_for_target(None).expect("native platform is valid")
}

/// BuildKit's automatic platform arguments for one frontend target.
///
/// The build platform is the worker that executes RUN, while the target comes
/// from the solve's `platform` frontend option. Build arguments are applied by
/// the caller after this map so explicit overrides retain BuildKit precedence.
pub fn automatic_platform_args_for_target(
    target: Option<&str>,
) -> Result<HashMap<String, String>, DockerfileBuildError> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        other => other,
    };
    let build_platform = format!("linux/{arch}");
    let target = match target {
        Some(target) => parse_buildkit_platform(target)?,
        None => BuildkitPlatform {
            formatted: build_platform.clone(),
            os: "linux".to_string(),
            os_version: String::new(),
            architecture: arch.to_string(),
            variant: String::new(),
        },
    };
    Ok(HashMap::from([
        ("BUILDPLATFORM".to_string(), build_platform),
        ("BUILDOS".to_string(), "linux".to_string()),
        // OCI platform variants and OS versions are empty on the native Linux
        // host, but BuildKit still defines the automatic ARGs.  Keeping the
        // empty values is important: `${TARGETVARIANT}` and
        // `${TARGETOSVERSION}` are valid expressions and must not be treated
        // as undeclared variables by the frontend phase.
        ("BUILDOSVERSION".to_string(), String::new()),
        ("BUILDARCH".to_string(), arch.to_string()),
        ("BUILDVARIANT".to_string(), String::new()),
        ("TARGETPLATFORM".to_string(), target.formatted),
        ("TARGETOS".to_string(), target.os),
        ("TARGETOSVERSION".to_string(), target.os_version),
        ("TARGETARCH".to_string(), target.architecture),
        ("TARGETVARIANT".to_string(), target.variant),
    ]))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BuildkitPlatform {
    formatted: String,
    os: String,
    os_version: String,
    architecture: String,
    variant: String,
}

fn output_platform_for_config(
    target: Option<&str>,
    base: &BaseConfig,
) -> Result<BuildkitPlatform, DockerfileBuildError> {
    let mut platform = match target {
        Some(target) => parse_buildkit_platform(target)?,
        None => automatic_platform_args_for_target(None).map(|args| BuildkitPlatform {
            formatted: args["TARGETPLATFORM"].clone(),
            os: args["TARGETOS"].clone(),
            os_version: args["TARGETOSVERSION"].clone(),
            architecture: args["TARGETARCH"].clone(),
            variant: args["TARGETVARIANT"].clone(),
        })?,
    };
    let same_os_arch = base.os.as_deref() == Some(platform.os.as_str())
        && base.architecture.as_deref() == Some(platform.architecture.as_str());
    if target.is_none() {
        if let (Some(os), Some(architecture)) = (&base.os, &base.architecture) {
            platform.os = os.clone();
            platform.architecture = architecture.clone();
            platform.os_version = base.os_version.clone().unwrap_or_default();
            platform.variant = base.variant.clone().unwrap_or_default();
        }
    } else if same_os_arch {
        if platform.os_version.is_empty() {
            platform.os_version = base.os_version.clone().unwrap_or_default();
        }
        if platform.variant.is_empty() {
            platform.variant = base.variant.clone().unwrap_or_default();
        }
    }
    Ok(platform)
}

fn parse_buildkit_platform(value: &str) -> Result<BuildkitPlatform, DockerfileBuildError> {
    let parts = value.split('/').collect::<Vec<_>>();
    if !(2..=3).contains(&parts.len()) || parts.iter().any(|part| part.is_empty()) {
        return Err(DockerfileBuildError::Invalid(format!(
            "invalid target platform {value}: expected OS/architecture[/variant]"
        )));
    }
    let (raw_os, raw_options) = match parts[0].split_once('(') {
        Some((os, options)) if options.ends_with(')') => {
            (os, Some(&options[..options.len() - 1]))
        }
        Some(_) => {
            return Err(DockerfileBuildError::Invalid(format!(
                "invalid target platform OS component: {}",
                parts[0]
            )))
        }
        None => (parts[0], None),
    };
    if raw_os.is_empty()
        || !raw_os
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(DockerfileBuildError::Invalid(format!(
            "invalid target platform OS component: {}",
            parts[0]
        )));
    }
    let os = match raw_os.to_ascii_lowercase().as_str() {
        "macos" => "darwin".to_string(),
        other => other.to_string(),
    };
    let architecture = match parts[1].to_ascii_lowercase().as_str() {
        "x86_64" | "x86-64" => "amd64".to_string(),
        "aarch64" => "arm64".to_string(),
        "i386" => "386".to_string(),
        "armhf" => "arm".to_string(),
        other => other.to_string(),
    };
    if !architecture
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(DockerfileBuildError::Invalid(format!(
            "invalid target platform architecture: {}",
            parts[1]
        )));
    }
    let variant = parts.get(2).copied().unwrap_or("").to_ascii_lowercase();
    if !variant
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(DockerfileBuildError::Invalid(format!(
            "invalid target platform variant: {variant}"
        )));
    }
    let raw_options = raw_options.unwrap_or("");
    let raw_os_version = raw_options.split('+').next().unwrap_or("");
    let os_version = percent_decode_platform_option(raw_os_version)?;
    let formatted_os = if raw_options.is_empty() {
        os.clone()
    } else {
        format!("{os}({raw_options})")
    };
    let formatted = if variant.is_empty() {
        format!("{formatted_os}/{architecture}")
    } else {
        format!("{formatted_os}/{architecture}/{variant}")
    };
    Ok(BuildkitPlatform {
        formatted,
        os,
        os_version,
        architecture,
        variant,
    })
}

fn percent_decode_platform_option(value: &str) -> Result<String, DockerfileBuildError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(DockerfileBuildError::Invalid(
                "invalid percent escape in target OS version".to_string(),
            ));
        }
        let hex = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        let high = hex(bytes[index + 1]);
        let low = hex(bytes[index + 2]);
        let (Some(high), Some(low)) = (high, low) else {
            return Err(DockerfileBuildError::Invalid(
                "invalid percent escape in target OS version".to_string(),
            ));
        };
        decoded.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(decoded).map_err(|_| {
        DockerfileBuildError::Invalid("target OS version is not UTF-8".to_string())
    })
}

fn validate_from_expression(value: &str, args: &HashMap<String, String>) -> Result<(), DockerfileBuildError> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'$' { index += 1; continue; }
        index += 1;
        let start = if bytes.get(index) == Some(&b'{') { index += 1; index } else { index };
        while bytes.get(index).is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_') { index += 1; }
        let name = &value[start..index];
        if bytes.get(start - 1) == Some(&b'{') && bytes.get(index) == Some(&b'}') { index += 1; }
        if !name.is_empty() && !args.contains_key(name) {
            return Err(DockerfileBuildError::Invalid(format!("FROM --platform expression references undeclared build argument: {name}")));
        }
    }
    Ok(())
}

/// Consume BuildKit heredoc bodies before instruction dispatch. Bodies are
/// deliberately appended to their introducing instruction so tokens such as
/// `echo`, `BEGIN`, or a shebang can never be parsed as Dockerfile keywords.
fn dockerfile_instructions(contents: &str) -> Result<Vec<String>, DockerfileBuildError> {
    let prepared = preprocess_dockerfile(contents)?;
    let lines = prepared.lines().collect::<Vec<_>>();
    let mut result = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let raw = lines[index];
        let keyword = raw.split_whitespace().next().unwrap_or("").to_ascii_uppercase();
        if !matches!(keyword.as_str(), "RUN" | "COPY" | "ADD" | "ONBUILD") {
            result.push(raw.to_string());
            index += 1;
            continue;
        }
        let markers = raw.split_whitespace().filter_map(|word| word.strip_prefix("<<")).map(|word| {
            let (strip_tabs, word) = word.strip_prefix('-').map(|word| (true, word)).unwrap_or((false, word));
            (word.trim_matches(|c| c == '\'' || c == '"').to_string(), strip_tabs)
        }).filter(|(delimiter, _)| !delimiter.is_empty()).collect::<Vec<_>>();
        if markers.is_empty() {
            result.push(raw.to_string());
            index += 1;
            continue;
        }
        let mut logical = raw.to_string();
        index += 1;
        for (delimiter, strip_tabs) in markers {
            let mut body = String::new();
            let mut terminated = false;
            while index < lines.len() {
                let candidate = if strip_tabs { lines[index].trim_start_matches('\t') } else { lines[index] };
                if candidate == delimiter {
                    index += 1;
                    terminated = true;
                    break;
                }
                if !body.is_empty() { body.push('\n'); }
                body.push_str(candidate);
                index += 1;
            }
            if !terminated {
                return Err(DockerfileBuildError::Invalid(format!("unterminated heredoc delimiter: {delimiter}")));
            }
            logical.push('\n');
            logical.push_str(&body);
        }
        result.push(logical);
    }
    Ok(result)
}


fn build_stage_dependency_graph(
    stages: &[StageSpec],
    named_contexts: &HashMap<String, PathBuf>,
) -> Result<Vec<Vec<usize>>, DockerfileBuildError> {
    let mut names = HashMap::new();
    for (index, stage) in stages.iter().enumerate() {
        if let Some(name) = stage.name.as_deref() {
            if names.insert(name.to_ascii_lowercase(), index).is_some() {
                return Err(DockerfileBuildError::Invalid(format!(
                    "duplicate Dockerfile stage name: {name}"
                )));
            }
        }
    }

    let mut graph = Vec::with_capacity(stages.len());
    for (index, stage) in stages.iter().enumerate() {
        let mut dependencies = stage
            .copy_from
            .iter()
            .chain(stage.copy_from_after_run.iter())
            .filter_map(|copy| {
                if named_contexts.contains_key(&copy.from) {
                    return None;
                }
                if let Ok(dependency) = copy.from.parse::<usize>() {
                    Some(Ok(dependency))
                } else {
                    names
                        .get(&copy.from.to_ascii_lowercase())
                        .copied()
                        .map(Ok)
                        .or_else(|| {
                            Some(Err(DockerfileBuildError::Invalid(format!(
                                "unknown COPY --from source: {}",
                                copy.from
                            ))))
                        })
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        // `FROM base` selects an earlier named stage before any registry
        // reference of the same spelling. Make that filesystem dependency
        // explicit so its RUN steps cannot be scheduled against another
        // stage's rootfs.
        if let Some(dependency) = names.get(&stage.base.to_ascii_lowercase()).copied() {
            dependencies.push(dependency);
        }
        dependencies.sort_unstable();
        dependencies.dedup();
        for dependency in &dependencies {
            if *dependency >= index {
                return Err(DockerfileBuildError::Invalid(format!(
                    "COPY --from stage {dependency} must reference an earlier stage"
                )));
            }
        }
        graph.push(dependencies);
    }
    Ok(graph)
}

fn earlier_stage_aliases(
    stages: &[StageSpec],
) -> Result<Vec<HashMap<String, usize>>, DockerfileBuildError> {
    let mut aliases = HashMap::new();
    let mut snapshots = Vec::with_capacity(stages.len());
    for (index, stage) in stages.iter().enumerate() {
        snapshots.push(aliases.clone());
        if let Some(name) = stage.name.as_deref() {
            if aliases.insert(name.to_ascii_lowercase(), index).is_some() {
                return Err(DockerfileBuildError::Invalid(format!(
                    "duplicate Dockerfile stage name: {name}"
                )));
            }
        }
    }
    Ok(snapshots)
}

fn build_stage_execution_batches(
    dependencies: &[Vec<usize>],
) -> Result<Vec<Vec<usize>>, DockerfileBuildError> {
    let stage_count = dependencies.len();
    let mut completed = vec![false; stage_count];
    let mut batches = Vec::new();
    while completed.iter().any(|done| !done) {
        let mut ready = dependencies
            .iter()
            .enumerate()
            .filter(|(index, _)| !completed[*index])
            .filter(|(_, required)| {
                required
                    .iter()
                    .all(|dependency| *dependency < stage_count && completed[*dependency])
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        ready.sort_unstable();
        if ready.is_empty() {
            return Err(DockerfileBuildError::Invalid(
                "Dockerfile stage dependency graph contains a cycle".to_string(),
            ));
        }
        for index in &ready {
            completed[*index] = true;
        }
        batches.push(ready);
    }
    Ok(batches)
}

/// Append a length-prefixed identity field. The tag keeps fields
/// domain-separated so adjacent values cannot be re-parsed ambiguously.
fn append_stage_identity_str(buffer: &mut Vec<u8>, tag: &str, value: &str) {
    buffer.extend_from_slice(tag.as_bytes());
    buffer.push(0);
    buffer.extend_from_slice(&(value.len() as u64).to_be_bytes());
    buffer.extend_from_slice(value.as_bytes());
}

fn append_stage_identity_opt_str(buffer: &mut Vec<u8>, tag: &str, value: &Option<String>) {
    append_stage_identity_str(buffer, tag, value.as_deref().unwrap_or("\0absent"));
}

fn append_stage_identity_u64(buffer: &mut Vec<u8>, tag: &str, value: u64) {
    append_stage_identity_str(buffer, tag, &value.to_string());
}

fn append_stage_identity_bool(buffer: &mut Vec<u8>, tag: &str, value: bool) {
    append_stage_identity_str(buffer, tag, if value { "1" } else { "0" });
}

fn append_stage_identity_owner(buffer: &mut Vec<u8>, tag: &str, owner: &Option<CopyOwner>) {
    match owner {
        None => append_stage_identity_str(buffer, tag, "\0absent"),
        Some(CopyOwner::Numeric(uid, gid)) => {
            append_stage_identity_str(buffer, tag, &format!("n:{uid}:{gid}"));
        }
        Some(CopyOwner::Named { user, group }) => {
            append_stage_identity_str(
                buffer,
                tag,
                &format!("s:{user}:{}", group.clone().unwrap_or_default()),
            );
        }
    }
}

/// Serialize every field of a stage that can change its built output. All
/// fields are included conservatively: adding an instruction field later must
/// extend this function, or stale checkpoints could be restored.
fn append_stage_spec_identity(buffer: &mut Vec<u8>, stage: &StageSpec) {
    append_stage_identity_str(buffer, "base", &stage.base);
    append_stage_identity_opt_str(buffer, "name", &stage.name);
    append_stage_identity_u64(
        buffer,
        "cf.after_run_index",
        stage
            .copy_from_after_run_index
            .map(|index| index as u64)
            .unwrap_or(u64::MAX),
    );
    for copy in stage
        .copy_from
        .iter()
        .chain(stage.copy_from_after_run.iter())
    {
        append_stage_identity_str(buffer, "cf.from", &copy.from);
        for source in &copy.srcs {
            append_stage_identity_str(buffer, "cf.src", source);
        }
        append_stage_identity_str(buffer, "cf.dest", &copy.dest);
        append_stage_identity_owner(buffer, "cf.owner", &copy.owner);
    }
    for copy in &stage.copy_paths {
        for source in &copy.srcs {
            append_stage_identity_str(buffer, "cp.src", source);
        }
        append_stage_identity_str(buffer, "cp.dest", &copy.dest);
        if let Some(chmod) = copy.chmod {
            append_stage_identity_u64(buffer, "cp.chmod", chmod as u64);
        } else {
            append_stage_identity_str(buffer, "cp.chmod", "\0absent");
        }
        append_stage_identity_owner(buffer, "cp.owner", &copy.owner);
        append_stage_identity_str(
            buffer,
            "cp.checksum",
            copy.checksum.as_deref().unwrap_or("\0absent"),
        );
        append_stage_identity_bool(buffer, "cp.parents", copy.parents);
        for exclude in &copy.excludes {
            append_stage_identity_str(buffer, "cp.exclude", exclude);
        }
        append_stage_identity_bool(buffer, "cp.extract", copy.extract_archives);
        append_stage_identity_str(
            buffer,
            "cp.inline",
            copy.inline_content.as_deref().unwrap_or("\0absent"),
        );
    }
    match &stage.healthcheck {
        Some(health) => {
            for probe in &health.test {
                append_stage_identity_str(buffer, "hc.test", probe);
            }
            append_stage_identity_u64(buffer, "hc.interval", health.interval_nanos);
            append_stage_identity_u64(buffer, "hc.timeout", health.timeout_nanos);
            append_stage_identity_u64(buffer, "hc.retries", health.retries as u64);
            append_stage_identity_u64(buffer, "hc.start_period", health.start_period_nanos);
            append_stage_identity_u64(buffer, "hc.start_interval", health.start_interval_nanos);
        }
        None => append_stage_identity_str(buffer, "hc", "\0absent"),
    }
    for entry in &stage.env {
        append_stage_identity_str(buffer, "env", entry);
    }
    let mut args = stage.args.iter().collect::<Vec<_>>();
    args.sort_unstable();
    for (key, value) in args {
        append_stage_identity_str(buffer, "arg", &format!("{key}={value}"));
    }
    let mut labels = stage.labels.iter().collect::<Vec<_>>();
    labels.sort_unstable();
    for (key, value) in labels {
        append_stage_identity_str(buffer, "label", &format!("{key}={value}"));
    }
    append_stage_identity_opt_str(buffer, "workdir", &stage.workdir);
    append_stage_identity_opt_str(buffer, "user", &stage.user);
    append_stage_identity_opt_str(buffer, "stop_signal", &stage.stop_signal);
    append_stage_identity_opt_str(buffer, "author", &stage.author);
    for trigger in &stage.onbuild {
        append_stage_identity_str(buffer, "onbuild", trigger);
    }
    match &stage.entrypoint {
        Some(entrypoint) => {
            for part in entrypoint {
                append_stage_identity_str(buffer, "entrypoint", part);
            }
        }
        None => append_stage_identity_str(buffer, "entrypoint", "\0absent"),
    }
    match &stage.cmd {
        Some(cmd) => {
            for part in cmd {
                append_stage_identity_str(buffer, "cmd", part);
            }
        }
        None => append_stage_identity_str(buffer, "cmd", "\0absent"),
    }
    for part in &stage.shell {
        append_stage_identity_str(buffer, "shell", part);
    }
    for run in &stage.run {
        for arg in &run.args {
            append_stage_identity_str(buffer, "run.arg", arg);
        }
        append_stage_identity_bool(buffer, "run.shell", run._shell);
        for mount in &run.cache_mounts {
            append_stage_identity_str(buffer, "cache.target", &mount.target);
            append_stage_identity_str(buffer, "cache.id", &mount.id);
            append_stage_identity_str(
                buffer,
                "cache.sharing",
                match mount.sharing {
                    CacheSharing::Shared => "shared",
                    CacheSharing::Private => "private",
                    CacheSharing::Locked => "locked",
                },
            );
            append_stage_identity_u64(
                buffer,
                "cache.uid",
                mount.uid.map(u64::from).unwrap_or(u64::MAX),
            );
            append_stage_identity_u64(
                buffer,
                "cache.gid",
                mount.gid.map(u64::from).unwrap_or(u64::MAX),
            );
            append_stage_identity_u64(
                buffer,
                "cache.mode",
                mount.mode.map(u64::from).unwrap_or(u64::MAX),
            );
        }
        for mount in &run.secret_mounts {
            append_stage_identity_str(buffer, "secret.target", &mount.target);
            append_stage_identity_str(buffer, "secret.id", &mount.id);
            append_stage_identity_str(
                buffer,
                "secret.env",
                mount.env.as_deref().unwrap_or("\0absent"),
            );
            append_stage_identity_bool(buffer, "secret.required", mount.required);
            append_stage_identity_u64(buffer, "secret.uid", u64::from(mount.uid));
            append_stage_identity_u64(buffer, "secret.gid", u64::from(mount.gid));
            append_stage_identity_u64(buffer, "secret.mode", u64::from(mount.mode));
        }
        for mount in &run.ssh_mounts {
            append_stage_identity_str(buffer, "ssh.target", &mount.target);
            append_stage_identity_str(buffer, "ssh.id", &mount.id);
            append_stage_identity_bool(buffer, "ssh.required", mount.required);
            append_stage_identity_u64(buffer, "ssh.uid", u64::from(mount.uid));
            append_stage_identity_u64(buffer, "ssh.gid", u64::from(mount.gid));
            append_stage_identity_u64(buffer, "ssh.mode", u64::from(mount.mode));
        }
        for mount in &run.tmpfs_mounts {
            append_stage_identity_str(buffer, "tmpfs.target", &mount.target);
            append_stage_identity_u64(buffer, "tmpfs.size", mount.size.unwrap_or(u64::MAX));
            append_stage_identity_bool(buffer, "tmpfs.ro", mount.read_only);
        }
        for mount in &run.bind_mounts {
            append_stage_identity_str(buffer, "bind.source", &mount.source);
            append_stage_identity_str(buffer, "bind.target", &mount.target);
            append_stage_identity_bool(buffer, "bind.ro", mount.read_only);
        }
        append_stage_identity_str(
            buffer,
            "run.network",
            match run.network {
                None => "default",
                Some(DockerfileNetworkMode::Sandbox) => "sandbox",
                Some(DockerfileNetworkMode::None) => "none",
                Some(DockerfileNetworkMode::Host) => "host",
            },
        );
        append_stage_identity_str(
            buffer,
            "run.security",
            match run.security {
                DockerfileSecurityMode::Sandbox => "sandbox",
                DockerfileSecurityMode::Insecure => "insecure",
            },
        );
    }
    for port in &stage.exposed_ports {
        append_stage_identity_str(buffer, "expose", port);
    }
    for volume in &stage.volumes {
        append_stage_identity_str(buffer, "volume", volume);
    }
}

/// A stage consumes the build context when it COPYs from it directly or from
/// a named context; RUN-only stages never see context bytes.
fn stage_consumes_context(stage: &StageSpec) -> bool {
    !stage.copy_paths.is_empty()
        || !stage.copy_from.is_empty()
        || !stage.copy_from_after_run.is_empty()
}

/// Compute the content-addressed identity of every stage in Dockerfile order.
/// Identity = digest(stage instructions, context binding when the stage
/// consumes context, base image digest, parent stage identities, compression).
/// The context binding is whole-context (conservative): an unrelated context
/// edit invalidates every context-consuming stage rather than one slice.
/// Editing one stage's instructions changes only that identity and the
/// identities of its descendants; independent branches are unaffected.
fn stage_content_identities(
    stages: &[StageSpec],
    base_digests: &[String],
    context_binding_digest: &str,
    dependencies: &[Vec<usize>],
    compression: CompressionFormat,
) -> Result<Vec<String>, DockerfileBuildError> {
    if stages.len() != base_digests.len() || stages.len() != dependencies.len() {
        return Err(DockerfileBuildError::Invalid(
            "stage identity inputs must match the stage count".to_string(),
        ));
    }
    let mut identities: Vec<String> = Vec::with_capacity(stages.len());
    for (index, stage) in stages.iter().enumerate() {
        let mut buffer = Vec::new();
        // Checkpoints now retain both the context and RUN layers so a
        // restored stage reproduces its complete rootfs rather than just its
        // final delta. Invalidate checkpoints written by the old format.
        buffer.extend_from_slice(b"ferrocrate/stage-identity/v2\0");
        buffer.push(match compression {
            CompressionFormat::None => 0,
            CompressionFormat::Gzip => 1,
            CompressionFormat::Zstd => 2,
        });
        append_stage_identity_str(&mut buffer, "base", &base_digests[index]);
        append_stage_spec_identity(&mut buffer, stage);
        if stage_consumes_context(stage) {
            append_stage_identity_str(&mut buffer, "context", context_binding_digest);
        }
        for dependency in &dependencies[index] {
            let parent = identities.get(*dependency).ok_or_else(|| {
                DockerfileBuildError::Invalid(
                    "stage dependency graph references a later stage".to_string(),
                )
            })?;
            append_stage_identity_str(&mut buffer, "parent", parent);
        }
        identities.push(hex::encode(rvf_crypto::shake256_256(&buffer)));
    }
    Ok(identities)
}

fn parse_from(value: &str) -> Result<(String, Option<String>), DockerfileBuildError> {
    let parts = value.split_whitespace().collect::<Vec<_>>();
    if parts.is_empty() {
        return Err(DockerfileBuildError::Invalid(
            "invalid FROM instruction".to_string(),
        ));
    }
    let mut index = 0;
    let platform = if let Some(raw) = parts[index].strip_prefix("--platform=") {
        index += 1;
        Some(raw)
    } else if parts[index].eq_ignore_ascii_case("--platform") {
        index += 1;
        let raw = parts.get(index).copied().ok_or_else(|| {
            DockerfileBuildError::Invalid("FROM --platform requires a value".to_string())
        })?;
        index += 1;
        Some(raw)
    } else if parts[index].starts_with("--") {
        return Err(DockerfileBuildError::Unsupported(format!(
            "FROM option {} is not supported",
            parts[index]
        )));
    } else {
        None
    };

    if let Some(platform) = platform {
        validate_from_platform(platform)?;
    }
    let base = parts.get(index).ok_or_else(|| {
        DockerfileBuildError::Invalid("FROM requires an image reference".to_string())
    })?;
    index += 1;
    let name = if index == parts.len() {
        None
    } else if index + 2 == parts.len() && parts[index].eq_ignore_ascii_case("AS") {
        let name = parts[index + 1];
        if name.is_empty() || name.starts_with('-') {
            return Err(DockerfileBuildError::Invalid(
                "FROM stage name must be non-empty and not start with '-'".to_string(),
            ));
        }
        Some(name.to_string())
    } else {
        return Err(DockerfileBuildError::Invalid(
            "FROM accepts an image followed by optional AS stage name".to_string(),
        ));
    };
    Ok((base.to_string(), name))
}

fn resolve_workdir(current: Option<&str>, requested: &str) -> Result<String, DockerfileBuildError> {
    let requested = requested.trim();
    if requested.is_empty() || requested.contains('\0') {
        return Err(DockerfileBuildError::Invalid(
            "WORKDIR requires a non-empty path".to_string(),
        ));
    }
    let mut components = Vec::new();
    if !requested.starts_with('/') {
        if let Some(current) = current {
            for component in current.split('/') {
                if !component.is_empty() && component != "." {
                    components.push(component.to_string());
                }
            }
        }
    }
    for component in requested.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(DockerfileBuildError::Invalid(
                        "WORKDIR path escapes the image root".to_string(),
                    ));
                }
            }
            value => components.push(value.to_string()),
        }
    }
    if components.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(format!("/{}", components.join("/")))
    }
}

fn validate_from_platform(platform: &str) -> Result<(), DockerfileBuildError> {
    let (os, architecture) = platform.split_once('/').ok_or_else(|| {
        DockerfileBuildError::Invalid("FROM --platform must use OS/architecture form".to_string())
    })?;
    if !os.eq_ignore_ascii_case("linux") {
        return Err(DockerfileBuildError::Unsupported(format!(
            "FROM --platform={platform} is unsupported; only linux host output is available"
        )));
    }
    let expected = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "arm" => "arm",
        other => other,
    };
    if !architecture.eq_ignore_ascii_case(expected) {
        return Err(DockerfileBuildError::Unsupported(format!(
            "FROM --platform={platform} is unsupported; only linux/{expected} is available"
        )));
    }
    Ok(())
}

fn parse_copy_from(value: &str) -> Result<Option<CopyFromSpec>, DockerfileBuildError> {
    let tokens = value.split_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        return Ok(None);
    }
    let mut idx = 0;
    let mut from = None;
    let mut owner = None;
    while idx < tokens.len() && tokens[idx].starts_with("--") {
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
        } else if tokens[idx].starts_with("--chown=") {
            owner = Some(parse_copy_owner(
                tokens[idx].trim_start_matches("--chown="),
            )?);
            idx += 1;
        } else if tokens[idx] == "--chown" {
            if tokens.len() <= idx + 1 {
                return Err(DockerfileBuildError::Invalid(
                    "COPY --chown requires an owner".to_string(),
                ));
            }
            owner = Some(parse_copy_owner(tokens[idx + 1])?);
            idx += 2;
        } else {
            break;
        }
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
        srcs: tokens[idx..tokens.len() - 1]
            .iter()
            .map(|source| (*source).to_string())
            .collect(),
        dest: tokens[tokens.len() - 1].to_string(),
        owner,
    }))
}

fn parse_copy_spec(value: &str) -> Result<Option<CopySpec>, DockerfileBuildError> {
    if let Some((header, body)) = value.split_once('\n') {
        let header = header.trim();
        if let Some(marker) = header.split_whitespace().find(|word| word.starts_with("<<")) {
            let delimiter = marker.trim_start_matches("<<").trim_start_matches('-').trim_matches(|c| c == '\'' || c == '"');
            let mut tokens = header.split_whitespace().filter(|word| *word != marker).collect::<Vec<_>>();
            if delimiter.is_empty() || tokens.is_empty() {
                return Err(DockerfileBuildError::Invalid("COPY heredoc requires a destination".to_string()));
            }
            let dest = tokens.pop().unwrap().to_string();
            if tokens.iter().any(|token| token.starts_with("--")) {
                return Err(DockerfileBuildError::Unsupported("COPY heredoc flags are not supported".to_string()));
            }
            return Ok(Some(CopySpec { srcs: Vec::new(), dest, chmod: None, owner: None, checksum: None, parents: false, excludes: Vec::new(), extract_archives: false, inline_content: Some(body.to_string()) }));
        }
    }
    let tokens = value.split_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        return Ok(None);
    }
    let mut args = Vec::new();
    let mut chmod = None;
    let mut owner = None;
    let mut checksum = None;
    let mut parents = false;
    let mut excludes = Vec::new();
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
        } else if let Some(raw_owner) = token.strip_prefix("--chown=") {
            owner = Some(parse_copy_owner(raw_owner)?);
        } else if token == "--chown" {
            let raw_owner = tokens.get(index + 1).ok_or_else(|| {
                DockerfileBuildError::Invalid("COPY --chown requires an owner".to_string())
            })?;
            owner = Some(parse_copy_owner(raw_owner)?);
            index += 1;
        } else if let Some(raw_checksum) = token.strip_prefix("--checksum=") {
            checksum = Some(parse_copy_checksum(raw_checksum)?);
        } else if token == "--checksum" {
            let raw_checksum = tokens.get(index + 1).ok_or_else(|| {
                DockerfileBuildError::Invalid("ADD --checksum requires a digest".to_string())
            })?;
            checksum = Some(parse_copy_checksum(raw_checksum)?);
            index += 1;
        } else if token == "--parents" {
            parents = true;
        } else if let Some(pattern) = token.strip_prefix("--exclude=") {
            if pattern.trim().is_empty() {
                return Err(DockerfileBuildError::Invalid(
                    "COPY --exclude requires a non-empty pattern".to_string(),
                ));
            }
            excludes.push(pattern.to_string());
        } else if token == "--exclude" {
            let pattern = tokens.get(index + 1).ok_or_else(|| {
                DockerfileBuildError::Invalid("COPY --exclude requires a pattern".to_string())
            })?;
            if pattern.trim().is_empty() {
                return Err(DockerfileBuildError::Invalid(
                    "COPY --exclude requires a non-empty pattern".to_string(),
                ));
            }
            excludes.push((*pattern).to_string());
            index += 1;
        } else if matches!(token, "--link" | "--link=true" | "--link=false") {
            // Each COPY is materialized into the stage's new context layer
            // before that layer is applied to the rootfs.  That already gives
            // this builder COPY --link's observable layer-isolation behavior;
            // cache/export metadata remains outside this single-layer model.
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
    Ok(Some(CopySpec {
        srcs,
        dest,
        chmod,
        owner,
        checksum,
        parents,
        excludes,
        extract_archives: false,
        inline_content: None,
    }))
}

fn parse_copy_checksum(raw: &str) -> Result<String, DockerfileBuildError> {
    let digest = raw.strip_prefix("sha256:").ok_or_else(|| {
        DockerfileBuildError::Invalid("ADD --checksum requires sha256:<64 hex>".to_string())
    })?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DockerfileBuildError::Invalid(
            "ADD --checksum requires sha256:<64 hex>".to_string(),
        ));
    }
    Ok(digest.to_ascii_lowercase())
}

fn parse_copy_owner(raw: &str) -> Result<CopyOwner, DockerfileBuildError> {
    let mut parts = raw.split(':');
    let user = parts.next().unwrap_or_default().trim();
    if user.is_empty() {
        return Err(DockerfileBuildError::Invalid(
            "COPY --chown user must not be empty".to_string(),
        ));
    }
    let group = match parts.next() {
        Some(value) if !value.is_empty() => Some(value.trim().to_string()),
        Some(_) => {
            return Err(DockerfileBuildError::Invalid(
                "COPY --chown gid must not be empty".to_string(),
            ));
        }
        None => None,
    };
    if parts.next().is_some() {
        return Err(DockerfileBuildError::Invalid(
            "COPY --chown accepts only uid[:gid]".to_string(),
        ));
    }
    if let Ok(uid) = user.parse::<u32>() {
        if let Some(group) = group.as_deref() {
            if let Ok(gid) = group.parse::<u32>() {
                return Ok(CopyOwner::Numeric(uid, gid));
            }
        } else {
            return Ok(CopyOwner::Numeric(uid, uid));
        }
    }
    Ok(CopyOwner::Named {
        user: user.to_string(),
        group,
    })
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

fn parse_cache_owner_id(kind: &str, raw: &str) -> Result<u32, DockerfileBuildError> {
    if raw.is_empty() {
        return Err(DockerfileBuildError::Invalid(format!(
            "cache mount {kind} must be an unsigned integer"
        )));
    }
    raw.parse::<u32>().map_err(|_| {
        DockerfileBuildError::Invalid(format!(
            "cache mount {kind} must be an unsigned integer: {raw}"
        ))
    })
}

fn apply_cache_mount_metadata(
    cache: &Path,
    target: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
) -> Result<(), DockerfileBuildError> {
    if let Some(mode) = mode {
        #[cfg(unix)]
        {
            fs::set_permissions(cache, fs::Permissions::from_mode(mode))?;
            fs::set_permissions(target, fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        {
            let _ = (cache, target, mode);
            return Err(DockerfileBuildError::Unsupported(
                "cache mount mode requires a Unix host".to_string(),
            ));
        }
    }
    if uid.is_some() || gid.is_some() {
        #[cfg(unix)]
        {
            use nix::unistd::{chown, Gid, Uid};
            use std::os::unix::fs::MetadataExt;
            let current = fs::metadata(cache)?;
            let owner = Uid::from_raw(uid.unwrap_or(current.uid()));
            let group = Gid::from_raw(gid.unwrap_or(current.gid()));
            chown(cache, Some(owner), Some(group)).map_err(|error| {
                DockerfileBuildError::Invalid(format!(
                    "cache mount cannot set owner {}:{}: {error}",
                    owner, group
                ))
            })?;
            chown(target, Some(owner), Some(group)).map_err(|error| {
                DockerfileBuildError::Invalid(format!(
                    "cache mount cannot set target owner {}:{}: {error}",
                    owner, group
                ))
            })?;
        }
        #[cfg(not(unix))]
        {
            let _ = (cache, target, uid, gid);
            return Err(DockerfileBuildError::Unsupported(
                "cache mount uid/gid requires a Unix host".to_string(),
            ));
        }
    }
    Ok(())
}

fn apply_secret_mount_metadata(
    target: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), DockerfileBuildError> {
    #[cfg(unix)]
    {
        use nix::unistd::{chown, Gid, Uid};
        fs::set_permissions(target, fs::Permissions::from_mode(mode))?;
        if !Uid::effective().is_root() {
            if uid == 0 && gid == 0 {
                // Bubblewrap maps the invoking host user to container 0:0.
                // Keeping the host ownership therefore produces BuildKit's
                // default ownership inside the RUN user namespace.
                return Ok(());
            }
            return Err(DockerfileBuildError::Unsupported(
                "rootless secret uid/gid require subordinate user-ID mappings".to_string(),
            ));
        }
        chown(
            target,
            Some(Uid::from_raw(uid)),
            Some(Gid::from_raw(gid)),
        )
        .map_err(|error| {
            DockerfileBuildError::Invalid(format!(
                "secret mount cannot set owner {uid}:{gid}: {error}"
            ))
        })?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (target, uid, gid, mode);
        Err(DockerfileBuildError::Unsupported(
            "secret mount metadata requires a Unix host".to_string(),
        ))
    }
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
        if let Some(paths) = try_parse_json_array(trimmed) {
            return Ok(paths);
        }
        // Not a JSON array: treat the text as whitespace-separated paths,
        // matching Docker's fallback.
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
        // Docker escape: `\$` yields a literal `$` so a variable reference
        // can reach the shell unexpanded (required for SSH_AUTH_SOCK-style
        // runtime variables inside RUN).
        if ch == '\\' && chars.peek().copied() == Some('$') {
            chars.next();
            out.push('$');
            continue;
        }
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
    start_interval_nanos: u64,
}

#[derive(Debug, Clone)]
struct RunSpec {
    args: Vec<String>,
    _shell: bool,
    cache_mounts: Vec<CacheMount>,
    secret_mounts: Vec<SecretMount>,
    ssh_mounts: Vec<SshMount>,
    tmpfs_mounts: Vec<TmpfsMount>,
    bind_mounts: Vec<BindMount>,
    network: Option<DockerfileNetworkMode>,
    security: DockerfileSecurityMode,
}

#[derive(Debug, Clone)]
struct CacheMount {
    target: String,
    id: String,
    sharing: CacheSharing,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheSharing {
    Shared,
    Private,
    Locked,
}

#[derive(Debug, Clone)]
struct SecretMount {
    target: String,
    id: String,
    env: Option<String>,
    required: bool,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Debug, Clone)]
struct SshMount {
    target: String,
    id: String,
    required: bool,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Debug, Clone)]
struct TmpfsMount {
    target: String,
    size: Option<u64>,
    read_only: bool,
}

#[derive(Debug, Clone)]
struct BindMount {
    source: String,
    target: String,
    read_only: bool,
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
    let mut start_interval = None;

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
            "interval" => interval = Some(parse_healthcheck_duration("interval", val)?),
            "timeout" => timeout = Some(parse_healthcheck_duration("timeout", val)?),
            "retries" => {
                let value = val.parse::<u32>().map_err(|_| {
                    DockerfileBuildError::Invalid(
                        "HEALTHCHECK retries must be a positive integer".to_string(),
                    )
                })?;
                if value == 0 {
                    return Err(DockerfileBuildError::Invalid(
                        "HEALTHCHECK retries must be a positive integer".to_string(),
                    ));
                }
                retries = Some(value);
            }
            "start-period" => start_period = Some(parse_healthcheck_duration("start-period", val)?),
            "start-interval" => {
                start_interval = Some(parse_healthcheck_duration("start-interval", val)?);
            }
            _ => {
                return Err(DockerfileBuildError::Invalid(format!(
                    "unsupported HEALTHCHECK flag: --{key}"
                )));
            }
        }
    }

    let mode = tokens
        .next()
        .ok_or_else(|| DockerfileBuildError::Invalid("missing HEALTHCHECK mode".to_string()))?;
    let rest = tokens.collect::<Vec<_>>().join(" ");
    let test = if mode.eq_ignore_ascii_case("CMD") {
        rest.split_whitespace().map(|s| s.to_string()).collect()
    } else if mode.eq_ignore_ascii_case("CMD-SHELL") {
        if rest.is_empty() {
            return Err(DockerfileBuildError::Invalid(
                "HEALTHCHECK command must not be empty".to_string(),
            ));
        }
        vec!["/bin/sh".to_string(), "-c".to_string(), rest]
    } else {
        return Err(DockerfileBuildError::Invalid(
            "unsupported HEALTHCHECK mode".to_string(),
        ));
    };
    if test.is_empty() {
        return Err(DockerfileBuildError::Invalid(
            "HEALTHCHECK command must not be empty".to_string(),
        ));
    }

    Ok(Some(HealthcheckSpec {
        test,
        interval_nanos: interval.unwrap_or(30_000_000_000),
        timeout_nanos: timeout.unwrap_or(5_000_000_000),
        retries: retries.unwrap_or(3),
        start_period_nanos: start_period.unwrap_or(0),
        start_interval_nanos: start_interval.unwrap_or(5_000_000_000),
    }))
}

fn parse_healthcheck_duration(name: &str, value: &str) -> Result<u64, DockerfileBuildError> {
    let nanos = parse_duration_to_nanos(value).ok_or_else(|| {
        DockerfileBuildError::Invalid(format!("HEALTHCHECK {name} must be a valid duration"))
    })?;
    if nanos == 0 {
        return Err(DockerfileBuildError::Invalid(format!(
            "HEALTHCHECK {name} must be greater than zero"
        )));
    }
    Ok(nanos)
}

#[cfg(test)]
fn parse_run(raw: &str, shell: &[String]) -> Result<RunSpec, DockerfileBuildError> {
    parse_run_with_workdir(raw, shell, "/")
}

fn docker_levenshtein(left: &str, right: &str) -> usize {
    let mut previous = (0..=right.len()).collect::<Vec<_>>();
    let mut current = vec![0; right.len() + 1];
    for (left_index, left_byte) in left.bytes().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right_byte) in right.bytes().enumerate() {
            current[right_index + 1] = (previous[right_index + 1] + 1)
                .min(current[right_index] + 1)
                .min(previous[right_index] + usize::from(left_byte != right_byte));
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}

fn docker_option_error(message: String, value: &str, options: &[&str]) -> String {
    let suggestion = options
        .iter()
        .filter_map(|option| {
            let distance = docker_levenshtein(value, option);
            (distance < 3).then_some((distance, *option))
        })
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, option)| option);
    match suggestion {
        Some(suggestion) if suggestion != value => {
            format!("{message} (did you mean {suggestion}?)")
        }
        _ => message,
    }
}

fn parse_run_with_workdir(
    raw: &str,
    shell: &[String],
    workdir: &str,
) -> Result<RunSpec, DockerfileBuildError> {
    let trimmed = raw.trim();
    if let Some((header, body)) = trimmed.split_once('\n') {
        if header.trim_start().starts_with("<<") {
            let mut args = shell.to_vec();
            args.push(body.to_string());
            return Ok(RunSpec {
                args,
                _shell: true,
                cache_mounts: Vec::new(),
                secret_mounts: Vec::new(),
                ssh_mounts: Vec::new(),
                tmpfs_mounts: Vec::new(),
                bind_mounts: Vec::new(),
                network: None,
                security: DockerfileSecurityMode::Sandbox,
            });
        }
    }
    let mut tokens = trimmed.split_whitespace().collect::<Vec<_>>();
    let original_token_count = tokens.len();
    let mut cache_mounts = Vec::new();
    let mut secret_mounts = Vec::new();
    let mut ssh_mounts = Vec::new();
    let mut tmpfs_mounts = Vec::new();
    let mut bind_mounts = Vec::new();
    let mut network = None;
    let mut security = DockerfileSecurityMode::Sandbox;
    let mut security_set = false;
    loop {
        if let Some(value) = tokens
            .first()
            .and_then(|token| token.strip_prefix("--network="))
        {
            if network.is_some() {
                return Err(DockerfileBuildError::Invalid(
                    "duplicate flag specified: --network".to_string(),
                ));
            }
            network = Some(match value {
                "default" => DockerfileNetworkMode::Sandbox,
                "none" => DockerfileNetworkMode::None,
                "host" => DockerfileNetworkMode::Host,
                other => {
                    return Err(DockerfileBuildError::Invalid(format!(
                        "invalid network mode {other:?}"
                    )))
                }
            });
            tokens.remove(0);
            continue;
        }
        if let Some(value) = tokens
            .first()
            .and_then(|token| token.strip_prefix("--security="))
        {
            if security_set {
                return Err(DockerfileBuildError::Invalid(
                    "duplicate flag specified: --security".to_string(),
                ));
            }
            security_set = true;
            security = match value {
                "sandbox" => DockerfileSecurityMode::Sandbox,
                "insecure" => DockerfileSecurityMode::Insecure,
                other => {
                    return Err(DockerfileBuildError::Invalid(format!(
                        "security {other:?} is not valid"
                    )))
                }
            };
            tokens.remove(0);
            continue;
        }
        let Some(mount) = tokens
            .first()
            .and_then(|token| token.strip_prefix("--mount="))
            .map(str::to_string)
        else {
            break;
        };
        tokens.remove(0);
        let mut kind = None;
        let mut target = None;
        let mut id = None;
        let mut source = None;
        let mut tmpfs_size = None;
        let mut read_only = false;
        let mut sharing = None;
        let mut required = None;
        let mut uid = None;
        let mut gid = None;
        let mut mode = None;
        let mut secret_env = None;
        for option in mount.split(',') {
            let (key, value) = option.split_once('=').unwrap_or((option, ""));
            match key {
                "type" => kind = Some(value),
                "target" | "dst" | "destination" => target = Some(value),
                "id" => id = Some(value),
                "source" | "src" => source = Some(value),
                "env" => secret_env = Some(value),
                "ro" | "readonly" => read_only = true,
                "rw" => read_only = false,
                "size" if !value.is_empty() => {
                    tmpfs_size = Some(parse_buildkit_byte_size("size", value)?)
                }
                "sharing" => {
                    if value.is_empty() {
                        return Err(DockerfileBuildError::Invalid(
                            "RUN cache mount sharing requires a value".to_string(),
                        ));
                    }
                    sharing = Some(value);
                }
                "uid" => uid = Some(value),
                "gid" => gid = Some(value),
                "mode" => mode = Some(value),
                "required" => {
                    required = Some(if value.is_empty() { "true" } else { value });
                }
                _ => {
                    let message = format!("unexpected key '{key}' in '{option}'");
                    return Err(DockerfileBuildError::Invalid(docker_option_error(
                        message,
                        key,
                        &[
                            "type", "from", "source", "target", "readonly", "id",
                            "sharing", "required", "size", "mode", "uid", "gid", "src",
                            "dst", "destination", "ro", "rw", "readwrite", "env",
                        ],
                    )));
                }
            }
        }
        match kind.unwrap_or("bind") {
            "cache" => {
                let sharing = match sharing {
                    None => CacheSharing::Shared,
                    Some(value) if value.eq_ignore_ascii_case("shared") => CacheSharing::Shared,
                    Some(value) if value.eq_ignore_ascii_case("private") => CacheSharing::Private,
                    Some(value) if value.eq_ignore_ascii_case("locked") => CacheSharing::Locked,
                    Some(value) => {
                        return Err(DockerfileBuildError::Invalid(docker_option_error(
                            format!("unsupported sharing value {value:?}"),
                            value,
                            &["shared", "private", "locked"],
                        )));
                    }
                };
                if required.is_some() || secret_env.is_some() {
                    return Err(DockerfileBuildError::Unsupported(
                        "RUN cache mount does not accept required/env".to_string(),
                    ));
                }
                if source.is_some() {
                    return Err(DockerfileBuildError::Unsupported(
                        "RUN cache mount source/from is not supported".to_string(),
                    ));
                }
                if read_only {
                    return Err(DockerfileBuildError::Unsupported(
                        "RUN cache mount readonly mode is not supported".to_string(),
                    ));
                }
                let uid = uid
                    .map(|value| parse_cache_owner_id("uid", value))
                    .transpose()?;
                let gid = gid
                    .map(|value| parse_cache_owner_id("gid", value))
                    .transpose()?;
                let mode = mode.map(parse_copy_mode).transpose()?;
                let target = target.ok_or_else(|| {
                    DockerfileBuildError::Invalid("cache mount requires target".to_string())
                })?;
                let target = resolve_run_mount_target(workdir, target)?;
                let id = match id {
                    Some(id) => id.to_string(),
                    None => format!("target-{}", hex::encode(Sha256::digest(target.as_bytes()))),
                };
                let id = validate_cache_id(&id)?;
                cache_mounts.push(CacheMount {
                    target,
                    id,
                    sharing,
                    uid,
                    gid,
                    mode,
                });
            }
            "secret" => {
                if sharing.is_some() {
                    return Err(DockerfileBuildError::Unsupported(
                        "RUN secret mount does not accept sharing".to_string(),
                    ));
                }
                if source.is_some() {
                    return Err(DockerfileBuildError::Unsupported(
                        "RUN secret mount does not accept source/src; provide the secret to the build request".to_string(),
                    ));
                }
                let required = match required {
                    None | Some("false") => false,
                    Some("true") => true,
                    Some(value) => {
                        return Err(DockerfileBuildError::Invalid(format!(
                            "RUN secret mount required must be true or false, got {value}"
                        )));
                    }
                };
                let id = id.or_else(|| target.and_then(|target| Path::new(target).file_name()?.to_str()))
                    .ok_or_else(|| DockerfileBuildError::Invalid(
                        "invalid secret mount: one of id or target is required".to_string(),
                    ))?;
                let id = validate_secret_id(id)?;
                let target = target
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("/run/secrets/{id}"));
                secret_mounts.push(SecretMount {
                    target: validate_cache_target(&target)?,
                    id,
                    env: secret_env
                        .filter(|value| !value.is_empty())
                        .map(str::to_string),
                    required,
                    uid: uid.map(|value| parse_cache_owner_id("uid", value)).transpose()?.unwrap_or(0),
                    gid: gid.map(|value| parse_cache_owner_id("gid", value)).transpose()?.unwrap_or(0),
                    mode: mode.map(parse_copy_mode).transpose()?.unwrap_or(0o400),
                });
            }
            "ssh" => {
                if secret_env.is_some() {
                    return Err(DockerfileBuildError::Unsupported(
                        "RUN ssh mount does not accept env".to_string(),
                    ));
                }
                if sharing.is_some() {
                    return Err(DockerfileBuildError::Unsupported(
                        "RUN ssh mount sharing is not supported".to_string(),
                    ));
                }
                if source.is_some() {
                    return Err(DockerfileBuildError::Unsupported(
                        "RUN ssh mount does not accept source/src; the agent socket is selected by the host environment".to_string(),
                    ));
                }
                let id = validate_secret_id(id.unwrap_or("default"))?;
                let target = target
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("/run/buildkit/ssh_agent.{id}"));
                let target = validate_cache_target(&target)?;
                if ssh_mounts
                    .iter()
                    .any(|mount: &SshMount| mount.target == target)
                {
                    return Err(DockerfileBuildError::Invalid(format!(
                        "duplicate SSH mount target: {target}"
                    )));
                }
                let required = match required {
                    None | Some("false") => false,
                    Some("true") => true,
                    Some(value) => return Err(DockerfileBuildError::Invalid(format!(
                        "RUN ssh mount required must be true or false, got {value}"
                    ))),
                };
                ssh_mounts.push(SshMount {
                    target,
                    id,
                    required,
                    uid: uid.map(|value| parse_cache_owner_id("uid", value)).transpose()?.unwrap_or(0),
                    gid: gid.map(|value| parse_cache_owner_id("gid", value)).transpose()?.unwrap_or(0),
                    mode: mode.map(parse_copy_mode).transpose()?.unwrap_or(0o600),
                });
            }
            "tmpfs" => {
                if sharing.is_some() || required.is_some() || secret_env.is_some() {
                    return Err(DockerfileBuildError::Unsupported(
                        "RUN tmpfs mount sharing/required options are not supported".to_string(),
                    ));
                }
                let target = target.ok_or_else(|| {
                    DockerfileBuildError::Invalid("tmpfs mount requires target".to_string())
                })?;
                let target = validate_cache_target(target)?;
                if tmpfs_mounts
                    .iter()
                    .any(|mount: &TmpfsMount| mount.target == target)
                {
                    return Err(DockerfileBuildError::Invalid(format!(
                        "duplicate tmpfs mount target: {target}"
                    )));
                }
                tmpfs_mounts.push(TmpfsMount {
                    target,
                    size: tmpfs_size,
                    read_only,
                });
            }
            "bind" => {
                if sharing.is_some() || required.is_some() || secret_env.is_some() {
                    return Err(DockerfileBuildError::Unsupported(
                        "RUN bind mount sharing/required options are not supported".to_string(),
                    ));
                }
                let source = source.unwrap_or(".").trim();
                if source.is_empty() {
                    return Err(DockerfileBuildError::Invalid(
                        "bind mount source must not be empty".to_string(),
                    ));
                }
                let target = target.ok_or_else(|| {
                    DockerfileBuildError::Invalid("bind mount requires target".to_string())
                })?;
                let target = resolve_run_mount_target(workdir, target)?;
                if bind_mounts
                    .iter()
                    .any(|mount: &BindMount| mount.target == target)
                {
                    return Err(DockerfileBuildError::Invalid(format!(
                        "duplicate bind mount target: {target}"
                    )));
                }
                bind_mounts.push(BindMount {
                    source: source.to_string(),
                    target,
                    read_only,
                });
            }
            other => {
                return Err(DockerfileBuildError::Invalid(docker_option_error(
                    format!("unsupported mount type {other:?}"),
                    other,
                    &["bind", "cache", "tmpfs", "secret", "ssh"],
                )));
            }
        }
    }
    // Dockerfile frontend flags belong to the instruction, not the shell
    // command.  In particular, BuildKit diagnoses the common `--mont` typo
    // before any RUN sandbox is started.  Preserve unrelated leading options
    // for their dedicated parsers (network/security/device); this branch is
    // deliberately narrow so it cannot reinterpret shell arguments.
    if let Some(token) = tokens.first().filter(|token| token.starts_with("--")) {
        if *token == "--" {
            tokens.remove(0);
        } else {
            let flag = token[2..].split_once('=').map(|(name, _)| name).unwrap_or(&token[2..]);
            if matches!(flag, "mount" | "network" | "security") {
                return Err(DockerfileBuildError::Invalid(format!(
                    "missing a value on flag: --{flag}"
                )));
            }
            if flag == "device" {
                return Err(DockerfileBuildError::Unsupported(
                    "RUN --device is not supported".to_string(),
                ));
            }
            return Err(DockerfileBuildError::Invalid(docker_option_error(
                format!("unknown flag: --{flag}"),
                flag,
                &["mount", "network", "security", "device"],
            )));
        }
    }
    let consumed_frontend_tokens = original_token_count.saturating_sub(tokens.len());
    let mut command = trimmed;
    for _ in 0..consumed_frontend_tokens {
        command = command.trim_start();
        command = command
            .find(char::is_whitespace)
            .map_or("", |separator| &command[separator..]);
    }
    let command = command.trim_start().to_string();
    if command.starts_with('[') {
        // A leading '[' may open JSON exec form or a POSIX '[' test utility
        // command. Only JSON exec form when the text actually parses as a
        // JSON array; otherwise fall back to shell form, matching Docker.
        if let Some(args) = try_parse_json_array(&command) {
            if !cache_mounts.is_empty()
                || !secret_mounts.is_empty()
                || !ssh_mounts.is_empty()
                || !tmpfs_mounts.is_empty()
                || !bind_mounts.is_empty()
            {
                return Err(DockerfileBuildError::Unsupported(
                    "cache mounts require shell-form RUN".to_string(),
                ));
            }
            return Ok(RunSpec {
                args,
                _shell: false,
                cache_mounts,
                secret_mounts,
                ssh_mounts,
                tmpfs_mounts,
                bind_mounts,
                network,
                security,
            });
        }
        // Not a JSON array: shell form, so mount flags stay valid.
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
        secret_mounts,
        ssh_mounts,
        tmpfs_mounts,
        bind_mounts,
        network,
        security,
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

/// BuildKit resolves relative cache and bind mount targets against the current
/// stage workdir. Normalize them while rejecting parent traversal before a
/// target can reach the rootfs mount setup.
fn resolve_run_mount_target(workdir: &str, target: &str) -> Result<String, DockerfileBuildError> {
    if target.starts_with('/') {
        return validate_cache_target(target);
    }
    if target.is_empty()
        || Path::new(target)
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(DockerfileBuildError::Invalid(
            "cache mount target must not contain parent traversal".to_string(),
        ));
    }
    let base = workdir.trim_end_matches('/');
    let resolved = if base.is_empty() {
        format!("/{target}")
    } else {
        format!("{base}/{target}")
    };
    validate_cache_target(&resolved)
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

fn validate_secret_id(id: &str) -> Result<String, DockerfileBuildError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(DockerfileBuildError::Invalid(
            "secret mount id contains invalid characters".to_string(),
        ));
    }
    Ok(id.to_string())
}

fn has_sensitive_mounts(stages: &[StageSpec]) -> bool {
    stages.iter().any(|stage| {
        stage
            .run
            .iter()
            .any(|run| !run.secret_mounts.is_empty() || !run.ssh_mounts.is_empty())
    })
}

fn split_dockerfile_tokens(raw: &str) -> Result<Vec<String>, DockerfileBuildError> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in raw.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            } else {
                current.push(character);
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            character if character.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            character => current.push(character),
        }
    }
    if escaped {
        return Err(DockerfileBuildError::Invalid(
            "Dockerfile instruction ends with an escape".to_string(),
        ));
    }
    if quote.is_some() {
        return Err(DockerfileBuildError::Invalid(
            "Dockerfile instruction has unterminated quotes".to_string(),
        ));
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

fn parse_env(raw: &str) -> Result<Vec<String>, DockerfileBuildError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(DockerfileBuildError::Invalid(
            "ENV requires key and value".to_string(),
        ));
    }
    let tokens = split_dockerfile_tokens(trimmed)?;
    if tokens.iter().any(|entry| entry.contains('=')) {
        if tokens
            .iter()
            .any(|entry| entry.split_once('=').is_none_or(|(key, _)| key.is_empty()))
        {
            return Err(DockerfileBuildError::Invalid(
                "ENV key=value entries require non-empty keys".to_string(),
            ));
        }
        return Ok(tokens);
    }

    if tokens.len() < 2 {
        return Err(DockerfileBuildError::Invalid(
            "ENV requires key and value".to_string(),
        ));
    }
    let key = &tokens[0];
    let value = tokens[1..].join(" ");
    Ok(vec![format!("{key}={value}")])
}

fn parse_labels(raw: &str) -> Result<HashMap<String, String>, DockerfileBuildError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(HashMap::new());
    }
    let mut out = HashMap::new();
    let tokens = split_dockerfile_tokens(trimmed)?;
    for token in tokens {
        if let Some((key, value)) = token.split_once('=') {
            if key.is_empty() {
                return Err(DockerfileBuildError::Invalid(
                    "LABEL key must not be empty".to_string(),
                ));
            }
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

fn parse_exposed_ports(raw: &str) -> Result<Vec<String>, DockerfileBuildError> {
    let tokens = raw.split_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        return Err(DockerfileBuildError::Invalid(
            "EXPOSE requires at least one port".to_string(),
        ));
    }
    tokens
        .into_iter()
        .map(|token| {
            let (port, protocol) = token
                .split_once('/')
                .map_or((token, "tcp"), |(p, proto)| (p, proto));
            let port = port.parse::<u16>().map_err(|_| {
                DockerfileBuildError::Invalid(format!("EXPOSE port is invalid: {token}"))
            })?;
            if port == 0 {
                return Err(DockerfileBuildError::Invalid(format!(
                    "EXPOSE port is invalid: {token}"
                )));
            }
            let protocol = protocol.to_ascii_lowercase();
            if !matches!(protocol.as_str(), "tcp" | "udp" | "sctp") {
                return Err(DockerfileBuildError::Invalid(format!(
                    "EXPOSE protocol is invalid: {token}"
                )));
            }
            Ok(format!("{port}/{protocol}"))
        })
        .collect()
}

fn parse_stop_signal(raw: &str) -> Result<String, DockerfileBuildError> {
    let signal = raw.trim();
    if signal.is_empty() || signal.split_whitespace().count() != 1 {
        return Err(DockerfileBuildError::Invalid(
            "STOPSIGNAL requires one signal".to_string(),
        ));
    }
    let number = signal.strip_prefix("SIG").unwrap_or(signal);
    if number.chars().all(|character| character.is_ascii_digit()) {
        let value = number.parse::<u16>().map_err(|_| {
            DockerfileBuildError::Invalid("STOPSIGNAL number is invalid".to_string())
        })?;
        if (1..=64).contains(&value) {
            return Ok(value.to_string());
        }
        return Err(DockerfileBuildError::Invalid(
            "STOPSIGNAL number must be between 1 and 64".to_string(),
        ));
    }
    let normalized = signal.to_ascii_uppercase();
    let normalized = normalized.strip_prefix("SIG").unwrap_or(&normalized);
    if matches!(
        normalized,
        "ABRT"
            | "ALRM"
            | "BUS"
            | "CHLD"
            | "CONT"
            | "FPE"
            | "HUP"
            | "ILL"
            | "INT"
            | "KILL"
            | "PIPE"
            | "QUIT"
            | "SEGV"
            | "STOP"
            | "TERM"
            | "TSTP"
            | "TTIN"
            | "TTOU"
            | "USR1"
            | "USR2"
            | "WINCH"
    ) {
        return Ok(format!("SIG{normalized}"));
    }
    Err(DockerfileBuildError::Invalid(format!(
        "STOPSIGNAL is invalid: {signal}"
    )))
}

fn parse_maintainer(raw: &str) -> Result<String, DockerfileBuildError> {
    let maintainer = raw.trim();
    if maintainer.is_empty() || maintainer.contains('\0') {
        return Err(DockerfileBuildError::Invalid(
            "MAINTAINER requires a non-empty value".to_string(),
        ));
    }
    Ok(maintainer.to_string())
}

fn parse_onbuild(raw: &str) -> Result<String, DockerfileBuildError> {
    let trigger = raw.trim();
    let keyword = trigger
        .split_whitespace()
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DockerfileBuildError::Invalid("ONBUILD requires a trigger".to_string()))?;
    if matches!(
        keyword.to_ascii_uppercase().as_str(),
        "FROM" | "MAINTAINER" | "ONBUILD"
    ) {
        return Err(DockerfileBuildError::Invalid(format!(
            "ONBUILD cannot trigger {keyword}"
        )));
    }
    if trigger.as_bytes().contains(&0) {
        return Err(DockerfileBuildError::Invalid(
            "ONBUILD trigger contains NUL".to_string(),
        ));
    }
    Ok(trigger.to_string())
}

fn parse_exec_or_shell(raw: &str, shell: &[String]) -> Result<Vec<String>, DockerfileBuildError> {
    let trimmed = raw.trim();
    if trimmed.starts_with('[') {
        // Only JSON exec form when the text actually parses as a JSON array;
        // a POSIX '[' utility command falls back to shell form, like Docker.
        if let Some(args) = try_parse_json_array(trimmed) {
            return Ok(args);
        }
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
    try_parse_json_array(raw).ok_or_else(|| {
        DockerfileBuildError::Invalid(
            "invalid JSON array: expected a JSON string array".to_string(),
        )
    })
}

fn try_parse_json_array(raw: &str) -> Option<Vec<String>> {
    serde_json::from_str(raw).ok()
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

fn uid_map_has_initial_namespace_root(raw: &str) -> bool {
    let mut fields = raw.split_whitespace();
    matches!(
        (fields.next(), fields.next(), fields.next(), fields.next()),
        (Some("0"), Some("0"), Some("4294967295"), None)
    )
}

fn has_direct_root_authority() -> bool {
    nix::unistd::Uid::effective().is_root()
        && fs::read_to_string("/proc/self/uid_map")
            .map(|raw| uid_map_has_initial_namespace_root(&raw))
            .unwrap_or(true)
}

#[allow(clippy::too_many_arguments)]
fn run_stage_commands(
    rootfs: &Path,
    runs: &[RunSpec],
    env: &[String],
    workdir: Option<&str>,
    user: Option<&str>,
    cache_root: &Path,
    secrets: &HashMap<String, PathBuf>,
    context_dir: &Path,
    control: &BuildControl,
    execution_options: &DockerfileExecutionOptions,
) -> Result<(), DockerfileBuildError> {
    let seccomp_profile = load_build_seccomp_profile()?;
    let limits = &control.limits;
    // A daemon re-executed in a root-mapped user namespace has euid 0 but
    // cannot use the direct mount/chroot sandbox. Treat it as rootless so
    // bubblewrap supplies the nested mount, pid, and proc namespaces.
    let running_as_root = has_direct_root_authority();
    fs::create_dir_all(cache_root)?;
    for (run_index, run) in runs.iter().enumerate() {
        if run.args.is_empty() {
            return Err(DockerfileBuildError::Invalid(
                "RUN instruction produced empty command".to_string(),
            ));
        }
        let rootless_bwrap = if running_as_root {
            None
        } else {
            Some(crate::rootless::bubblewrap_path().ok_or_else(|| {
                DockerfileBuildError::Invalid(
                    "rootless RUN sandbox requires trusted bubblewrap (bwrap)".to_string(),
                )
            })?)
        };
        let network_mode = run.network.unwrap_or(execution_options.network_mode);
        if network_mode == DockerfileNetworkMode::Host
            && !execution_options.allow_network_host
        {
            return Err(DockerfileBuildError::Invalid(
                "entitlement network.host is not allowed".to_string(),
            ));
        }
        let security_insecure = run.security == DockerfileSecurityMode::Insecure;
        if security_insecure && !execution_options.allow_security_insecure {
            return Err(DockerfileBuildError::Invalid(
                "entitlement security.insecure is not allowed".to_string(),
            ));
        }
        let rootful_insecure_dev = if running_as_root && security_insecure {
            let target = validate_mount_target(rootfs, "/dev", "insecure build device")?;
            fs::create_dir_all(&target)?;
            Some(target)
        } else {
            None
        };
        provision_build_network_files(rootfs)?;
        let cgroup_namespace = child_requires_cgroup_namespace(execution_options);
        let cgroup_mount_target = cgroup_namespace.then(|| rootfs.join("sys/fs/cgroup"));
        let cgroup_mount_existed = cgroup_mount_target.as_ref().is_some_and(|target| target.exists());
        if let Some(target) = &cgroup_mount_target {
            fs::create_dir_all(target)?;
        }
        let proc_mount_target = running_as_root.then(|| rootfs.join("proc"));
        let proc_mount_existed = proc_mount_target.as_ref().is_some_and(|target| target.exists());
        if let Some(target) = &proc_mount_target {
            fs::create_dir_all(target)?;
        }
        let mut cmd = if let Some(bwrap) = &rootless_bwrap {
            let mut command = Command::new(bwrap);
            command
                .args([
                    "--die-with-parent",
                    "--unshare-user",
                    "--unshare-pid",
                    "--unshare-uts",
                    "--uid",
                    "0",
                    "--gid",
                    "0",
                    "--bind",
                ])
                .arg(rootfs)
                .arg("/")
                .arg("--proc")
                .arg("/proc")
                // Cargo and other build tools open /dev/null while spawning
                // their compiler children. Without a sandbox-local /dev,
                // those children fail with a misleading ENOENT even though
                // the stage executable is present.
                .arg("--dev")
                .arg("/dev")
                .arg("--chdir")
                .arg(
                    workdir
                        .filter(|dir| !dir.trim().is_empty())
                        .map(|dir| {
                            if dir.starts_with('/') {
                                dir.to_string()
                            } else {
                                format!("/{dir}")
                            }
                        })
                        .unwrap_or_else(|| "/".to_string()),
                );
            if network_mode == DockerfileNetworkMode::None {
                command.arg("--unshare-net");
            }
            if !security_insecure {
                command.arg("--cap-drop").arg("ALL");
                for capability in dockerfile_default_capabilities() {
                    command
                        .arg("--cap-add")
                        .arg(format!("{capability:?}"));
                }
            } else {
                for device in [
                    "/dev/kmsg",
                    "/dev/cuse",
                    "/dev/fuse",
                    "/dev/kvm",
                    "/dev/net/tun",
                    "/dev/loop-control",
                ] {
                    command.arg("--dev-bind-try").arg(device).arg(device);
                }
            }
            if cgroup_namespace {
                command.arg("--unshare-cgroup-try");
                command
                    .arg("--ro-bind")
                    .arg("/sys/fs/cgroup")
                    .arg("/sys/fs/cgroup");
            }
            command
        } else {
            let mut command = Command::new(&run.args[0]);
            command.args(&run.args[1..]);
            command
        };
        cmd.stdin(Stdio::null());
        // Capture every RUN stream. Besides enforcing the optional output
        // cap, this lets a failed build report the command's actual output
        // instead of leaving the user with a bare exit status.
        let output_cap = limits.max_output_bytes;
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

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
        let limits = control.limits.clone();
        let child_limits = limits.clone();
        let run_cgroup = prepare_build_run_cgroup(execution_options, run_index)?;
        let child_cgroup = run_cgroup.as_ref().map(|cgroup| cgroup.path.clone());
        let child_cgroup_mount = cgroup_mount_target.clone();
        let child_proc_mount = proc_mount_target.clone();
        let child_ulimits = execution_options.ulimits.clone();
        let child_security_insecure = security_insecure;
        let ssh_socket = std::env::var_os("FERROCRATE_BUILD_SSH_AUTH_SOCK")
            .or_else(|| std::env::var_os("SSH_AUTH_SOCK"))
            .map(PathBuf::from);
        let mut ssh_specs = Vec::new();
        let mut ssh_env_target: Option<String> = None;
        let mut ssh_sources = HashSet::new();
        for mount_spec in &run.ssh_mounts {
            // The current executor exposes one authorized host agent socket;
            // retain the parsed identity for Dockerfile/API compatibility.
            let _ = mount_spec.id.as_str();
            let Some(source) = ssh_socket.clone() else {
                if mount_spec.required {
                    return Err(DockerfileBuildError::Invalid(
                        "required SSH mount has no FERROCRATE_BUILD_SSH_AUTH_SOCK or SSH_AUTH_SOCK"
                            .to_string(),
                    ));
                }
                continue;
            };
            if mount_spec.uid != 0 || mount_spec.gid != 0 || mount_spec.mode != 0o600 {
                return Err(DockerfileBuildError::Unsupported(
                    "SSH mount uid/gid/mode require an agent socket proxy and are not yet supported"
                        .to_string(),
                ));
            }
            let metadata = fs::symlink_metadata(&source).map_err(|err| {
                DockerfileBuildError::Invalid(format!(
                    "SSH agent socket {} cannot be inspected: {err}",
                    source.display()
                ))
            })?;
            if !source.is_absolute() {
                return Err(DockerfileBuildError::Invalid(format!(
                    "SSH agent source must be an absolute path: {}",
                    source.display()
                )));
            }
            #[cfg(unix)]
            if !metadata.file_type().is_socket() {
                return Err(DockerfileBuildError::Invalid(format!(
                    "SSH agent source is not a Unix socket: {}",
                    source.display()
                )));
            }
            #[cfg(not(unix))]
            {
                let _ = metadata;
                return Err(DockerfileBuildError::Unsupported(
                    "RUN --mount=type=ssh requires a Unix host".to_string(),
                ));
            }
            let target = validate_mount_target(&rootfs, &mount_spec.target, "ssh")?;
            if !ssh_sources.insert(target.clone()) {
                return Err(DockerfileBuildError::Invalid(format!(
                    "duplicate SSH mount target: {}",
                    mount_spec.target
                )));
            }
            if ssh_env_target.is_none() {
                ssh_env_target = Some(mount_spec.target.clone());
            }
            ssh_specs.push((source, target));
        }
        if let Some(ssh_auth_sock_target) = &ssh_env_target {
            // BuildKit semantics: inside the RUN the agent socket lives at its
            // mount point, so SSH_AUTH_SOCK must name the in-namespace target,
            // never the host-side rootfs path (which does not exist after
            // chroot). The host selector variable never crosses the boundary.
            cmd.env("SSH_AUTH_SOCK", ssh_auth_sock_target);
            cmd.env_remove("FERROCRATE_BUILD_SSH_AUTH_SOCK");
        }
        let mut ssh_mounted = Vec::new();
        for (index, (source, target)) in ssh_specs.iter().enumerate() {
            let backup = rootfs.join(format!(".ferrocrate-ssh-backup-{index}"));
            let existed = target.exists();
            if existed {
                if target.is_dir() {
                    return Err(DockerfileBuildError::Invalid(format!(
                        "SSH mount target is a directory: {}",
                        target.display()
                    )));
                }
                fs::rename(target, &backup)?;
            }
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::File::create(target)?;
            #[cfg(unix)]
            fs::set_permissions(target, fs::Permissions::from_mode(0o600))?;
            ssh_mounted.push((source.clone(), target.clone(), backup, existed));
        }
        let ssh_for_child = ssh_mounted
            .iter()
            .map(|(source, target, _, _)| (source.clone(), target.clone()))
            .collect::<Vec<_>>();
        let mut tmpfs_specs = Vec::new();
        let mut tmpfs_targets = Vec::new();
        let mut tmpfs_seen = HashSet::new();
        for mount_spec in &run.tmpfs_mounts {
            let target = validate_mount_target(&rootfs, &mount_spec.target, "tmpfs")?;
            if !tmpfs_seen.insert(target.clone()) {
                return Err(DockerfileBuildError::Invalid(format!(
                    "duplicate tmpfs mount target: {}",
                    mount_spec.target
                )));
            }
            let existed = target.exists();
            if existed && !target.is_dir() {
                return Err(DockerfileBuildError::Invalid(format!(
                    "tmpfs mount target is not a directory: {}",
                    mount_spec.target
                )));
            }
            if !existed {
                fs::create_dir_all(&target)?;
            }
            tmpfs_specs.push((target.clone(), mount_spec.size, mount_spec.read_only));
            tmpfs_targets.push((target, existed));
        }
        if let Some(size) = execution_options.shm_size {
            let target = validate_mount_target(&rootfs, "/dev/shm", "shared memory")?;
            if !tmpfs_seen.contains(&target) {
                let existed = target.exists();
                if existed && !target.is_dir() {
                    return Err(DockerfileBuildError::Invalid(
                        "/dev/shm is not a directory".to_string(),
                    ));
                }
                if !existed {
                    fs::create_dir_all(&target)?;
                }
                tmpfs_seen.insert(target.clone());
                tmpfs_specs.push((target.clone(), Some(size), false));
                tmpfs_targets.push((target, existed));
            }
        }
        let tmpfs_for_child = tmpfs_specs.clone();
        let mut bind_specs = Vec::new();
        let mut bind_seen = HashSet::new();
        for mount_spec in &run.bind_mounts {
            let source = safe_context_source(context_dir, &mount_spec.source)?;
            let source_is_dir = fs::metadata(&source)?.is_dir();
            let target = validate_mount_target(&rootfs, &mount_spec.target, "bind")?;
            if !bind_seen.insert(target.clone()) {
                return Err(DockerfileBuildError::Invalid(format!(
                    "duplicate bind mount target: {}",
                    mount_spec.target
                )));
            }
            if tmpfs_targets.iter().any(|(path, _)| path == &target) {
                return Err(DockerfileBuildError::Invalid(format!(
                    "bind mount target overlaps tmpfs target: {}",
                    mount_spec.target
                )));
            }
            if target.exists() && target.is_dir() != source_is_dir {
                return Err(DockerfileBuildError::Invalid(format!(
                    "bind mount source/target type mismatch: {}",
                    mount_spec.target
                )));
            }
            bind_specs.push((source, target, source_is_dir, mount_spec.read_only));
        }
        let mut bind_mounted = Vec::new();
        for (index, (source, target, source_is_dir, read_only)) in bind_specs.iter().enumerate() {
            let backup = rootfs.join(format!(".ferrocrate-bind-backup-{index}"));
            let existed = target.exists();
            if existed {
                fs::rename(target, &backup)?;
            } else if *source_is_dir {
                fs::create_dir_all(target)?;
            } else {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::File::create(target)?;
            }
            bind_mounted.push((source.clone(), target.clone(), backup, existed, *read_only));
        }
        let bind_for_child = bind_mounted
            .iter()
            .map(|(source, target, _, _, read_only)| (source.clone(), target.clone(), *read_only))
            .collect::<Vec<_>>();
        if rootless_bwrap.is_some() {
            for (target, _size, read_only) in &tmpfs_specs {
                let target = build_root_relative_path(&rootfs, target)?;
                cmd.arg("--tmpfs").arg(&target);
                if *read_only {
                    cmd.arg("--remount-ro").arg(&target);
                }
            }
            for (source, target, read_only) in &bind_for_child {
                let target = build_root_relative_path(&rootfs, target)?;
                cmd.arg(if *read_only { "--ro-bind" } else { "--bind" })
                    .arg(source)
                    .arg(target);
            }
            for (source, target) in &ssh_for_child {
                let target = build_root_relative_path(&rootfs, target)?;
                cmd.arg("--bind").arg(source).arg(target);
            }
            cmd.arg("--").args(&run.args);
        }
        // SAFETY: pre_exec runs in the child process between fork and exec to install
        // sandboxing primitives that must be process-local (namespaces/seccomp/chroot).
        unsafe {
            cmd.pre_exec(move || {
                create_build_process_group()?;
                if let Some(cgroup) = child_cgroup.as_ref() {
                    fs::write(cgroup.join("cgroup.procs"), std::process::id().to_string())
                        .map_err(|err| io::Error::new(err.kind(), format!(
                            "build pre_exec join cgroup {}: {err}", cgroup.display()
                        )))?;
                }
                if running_as_root {
                    setup_build_namespace_root(
                        should_isolate_build_network(network_mode),
                        child_cgroup.is_some(),
                    )
                    .map_err(|err| {
                        io::Error::new(
                            err.kind(),
                            format!("build pre_exec unshare root namespaces: {err}"),
                        )
                    })?;
                }
                #[cfg(target_os = "linux")]
                if let Some(target) = child_proc_mount.as_ref() {
                    mount(
                        Some("proc"),
                        target,
                        Some("proc"),
                        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                        None::<&str>,
                    )
                    .map_err(|err| {
                        io::Error::other(format!("build pre_exec mount proc: {err}"))
                    })?;
                }
                #[cfg(target_os = "linux")]
                if let Some(target) = rootful_insecure_dev.as_ref() {
                    mount_rootful_insecure_devices(target).map_err(|err| {
                        io::Error::new(err.kind(), format!(
                            "build pre_exec prepare insecure devices: {err}"
                        ))
                    })?;
                }
                #[cfg(target_os = "linux")]
                if let Some(target) = child_cgroup_mount.as_ref().filter(|_| running_as_root) {
                    mount(
                        Some("cgroup2"),
                        target,
                        Some("cgroup2"),
                        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                        None::<&str>,
                    )
                    .map_err(|err| {
                        io::Error::other(format!("build pre_exec mount cgroup2: {err}"))
                    })?;
                }
                #[cfg(unix)]
                for (target, size, read_only) in tmpfs_for_child.iter().filter(|_| running_as_root) {
                    let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
                    if *read_only {
                        flags |= MsFlags::MS_RDONLY;
                    }
                    let options = size.map(|bytes| format!("size={bytes}"));
                    mount(
                        None::<&str>,
                        target,
                        Some("tmpfs"),
                        flags,
                        options.as_deref(),
                    )
                    .map_err(|err| {
                        io::Error::other(format!("build pre_exec mount tmpfs: {err}"))
                    })?;
                }
                #[cfg(unix)]
                for (source, target, read_only) in bind_for_child.iter().filter(|_| running_as_root) {
                    mount(
                        Some(source),
                        target,
                        Some("bind"),
                        MsFlags::MS_BIND,
                        None::<&str>,
                    )
                    .map_err(|err| {
                        io::Error::other(format!("build pre_exec mount bind: {err}"))
                    })?;
                    if *read_only {
                        mount(
                            None::<&str>,
                            target,
                            Some("bind"),
                            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                            None::<&str>,
                        )
                        .map_err(|err| {
                            io::Error::other(format!("build pre_exec make bind read-only: {err}"))
                        })?;
                    }
                }
                #[cfg(unix)]
                for (source, target) in ssh_for_child.iter().filter(|_| running_as_root) {
                    mount(
                        Some(source),
                        target,
                        Some("bind"),
                        MsFlags::MS_BIND,
                        None::<&str>,
                    )
                    .map_err(|err| io::Error::other(format!("build pre_exec mount SSH agent: {err}")))?;
                }
                if running_as_root {
                    enter_build_rootfs(&command_rootfs, workdir.as_deref()).map_err(|err| {
                        io::Error::new(err.kind(), format!("build pre_exec enter rootfs: {err}"))
                    })?;
                    apply_build_identity(run_user.as_deref()).map_err(|err| {
                        io::Error::new(err.kind(), format!("build pre_exec set identity: {err}"))
                    })?;
                }
                if running_as_root && !child_security_insecure {
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
                    set_capabilities(&dockerfile_default_capabilities()).map_err(|err| {
                        io::Error::other(format!(
                            "build pre_exec set sandbox capabilities: {err}"
                        ))
                    })?;
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
                }
                apply_build_limits(&child_limits).map_err(|err| {
                    io::Error::new(err.kind(), format!("build pre_exec apply limits: {err}"))
                })?;
                apply_dockerfile_ulimits(&child_ulimits).map_err(|err| {
                    io::Error::new(err.kind(), format!("build pre_exec apply ulimits: {err}"))
                })?;
                Ok(())
            });
        }

        for mount in &run.secret_mounts {
            let Some(source) = secrets.get(&mount.id) else {
                if !mount.required {
                    continue;
                }
                return Err(DockerfileBuildError::Invalid(format!(
                    "secret mount source was not provided for id {}",
                    mount.id
                )));
            };
            let metadata = fs::symlink_metadata(source).map_err(|err| {
                DockerfileBuildError::Invalid(format!("secret {} cannot be read: {err}", mount.id))
            })?;
            if !metadata.file_type().is_file() || metadata.len() > 1024 * 1024 {
                return Err(DockerfileBuildError::Invalid(format!(
                    "secret {} must be a regular file no larger than 1 MiB",
                    mount.id
                )));
            }
            if let Some(name) = &mount.env {
                let value = fs::read(source)?;
                let value = String::from_utf8(value).map_err(|_| {
                    DockerfileBuildError::Invalid(format!(
                        "secret {} is not valid UTF-8 for environment variable {name}",
                        mount.id
                    ))
                })?;
                cmd.env(name, value);
            }
        }
        let mut mounted = Vec::new();
        for (index, mount) in run.cache_mounts.iter().enumerate() {
            let target = validate_mount_target(&rootfs, &mount.target, "cache")?;
            let backup = rootfs.join(format!(".ferrocrate-cache-backup-{index}"));
            let existed = target.exists();
            if existed {
                fs::rename(&target, &backup)?;
            }
            let persist = mount.sharing != CacheSharing::Private;
            let cache = if persist {
                cache_root.join(&mount.id)
            } else {
                cache_root.join("private").join(format!(
                    "{}-{index}-{}",
                    mount.id,
                    std::process::id()
                ))
            };
            reject_cache_path_symlinks(&cache)?;
            let lock = if mount.sharing == CacheSharing::Locked {
                let lock_path = cache_root.join("locks").join(format!("{}.lock", mount.id));
                reject_cache_path_symlinks(&lock_path)?;
                Some(acquire_cache_lock(&lock_path)?)
            } else {
                None
            };
            fs::create_dir_all(&cache)?;
            reject_cache_symlinks(&cache)?;
            fs::create_dir_all(&target)?;
            if persist {
                copy_path_recursive(&cache, &target)?;
            }
            apply_cache_mount_metadata(&cache, &target, mount.uid, mount.gid, mount.mode)?;
            mounted.push((target, backup, cache, existed, persist, lock));
        }
        let mut secret_mounted = Vec::new();
        for (index, mount) in run.secret_mounts.iter().enumerate() {
            if mount.env.is_some() {
                continue;
            }
            let Some(source) = secrets.get(&mount.id) else {
                continue;
            };
            let target = validate_mount_target(&rootfs, &mount.target, "secret")?;
            let backup = rootfs.join(format!(".ferrocrate-secret-backup-{index}"));
            let existed = target.exists();
            if existed {
                if target.is_dir() {
                    return Err(DockerfileBuildError::Invalid(format!(
                        "secret mount target is a directory: {}",
                        mount.target
                    )));
                }
                fs::rename(&target, &backup)?;
            }
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(source, &target)?;
            apply_secret_mount_metadata(&target, mount.uid, mount.gid, mount.mode)?;
            secret_mounted.push((target, backup, existed));
        }
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                for (target, backup, existed) in secret_mounted.iter().rev() {
                    let _ = fs::remove_file(target);
                    if *existed {
                        fs::rename(backup, target)?;
                    }
                }
                for (target, backup, cache, existed, persist, _lock) in mounted.iter().rev() {
                    let _ = fs::remove_dir_all(target);
                    if *existed {
                        fs::rename(backup, target)?;
                    }
                    if !persist {
                        let _ = fs::remove_dir_all(cache);
                    }
                }
                for (_source, target, backup, existed) in ssh_mounted.iter().rev() {
                    let _ = fs::remove_file(target);
                    if *existed {
                        fs::rename(backup, target)?;
                    }
                }
                for (target, existed) in tmpfs_targets.iter().rev() {
                    if !existed {
                        let _ = fs::remove_dir_all(target);
                    }
                }
                for (_source, target, backup, existed, _) in bind_mounted.iter().rev() {
                    if target.is_dir() {
                        let _ = fs::remove_dir_all(target);
                    } else {
                        let _ = fs::remove_file(target);
                    }
                    if *existed {
                        fs::rename(backup, target)?;
                    }
                }
                if let Some(cgroup) = run_cgroup {
                    let _ = cgroup.cleanup();
                }
                cleanup_cgroup_mount_stub(
                    cgroup_mount_target.as_deref(),
                    cgroup_mount_existed,
                    &rootfs,
                );
                if !proc_mount_existed {
                    if let Some(target) = proc_mount_target.as_ref() {
                        let _ = fs::remove_dir(target);
                    }
                }
                return Err(DockerfileBuildError::Invalid(format!(
                    "RUN sandbox spawn failed: {err}"
                )));
            }
        };
        let started = Instant::now();
        let output_total = Arc::new(AtomicU64::new(0));
        let output_exceeded = Arc::new(AtomicBool::new(false));
        let mut output_drains = Vec::new();
        let cap = output_cap.unwrap_or(u64::MAX);
        let mut child_streams: Vec<(&str, Box<dyn Read + Send>)> = Vec::new();
        if let Some(stream) = child.stdout.take() {
            child_streams.push(("stdout", Box::new(stream)));
        }
        if let Some(stream) = child.stderr.take() {
            child_streams.push(("stderr", Box::new(stream)));
        }
        for (name, stream) in child_streams {
            let total = Arc::clone(&output_total);
            let exceeded = Arc::clone(&output_exceeded);
            output_drains.push(thread::spawn(move || {
                let mut stream = stream;
                let mut captured = Vec::new();
                let mut buffer = [0u8; 8192];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            captured.extend_from_slice(&buffer[..read]);
                            let summed =
                                total.fetch_add(read as u64, Ordering::Relaxed) + read as u64;
                            if summed > cap {
                                exceeded.store(true, Ordering::Release);
                            }
                        }
                    }
                }
                (name, captured)
            }));
        }
        let status_result = loop {
            if let Some(status) = child.try_wait()? {
                break Ok(status);
            }
            if let Some(path) = limits.cancel_file.as_ref() {
                if path.exists() {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(DockerfileBuildError::Cancelled(format!(
                        "RUN cancelled by build control: {}",
                        path.display()
                    )));
                }
            }
            if limits
                .timeout
                .is_some_and(|timeout| started.elapsed() >= timeout)
            {
                let _ = child.kill();
                let _ = child.wait();
                break Err(DockerfileBuildError::LimitExceeded(
                    "RUN timed out by build control".to_string(),
                ));
            }
            if control.deadline_exceeded() {
                let _ = child.kill();
                let _ = child.wait();
                break Err(DockerfileBuildError::LimitExceeded(
                    "RUN aborted: build wall clock exceeded".to_string(),
                ));
            }
            if output_exceeded.load(Ordering::Acquire) {
                let _ = child.kill();
                let _ = child.wait();
                break Err(DockerfileBuildError::LimitExceeded(format!(
                    "RUN output exceeded {cap} bytes"
                )));
            }
            thread::sleep(Duration::from_millis(20));
        };
        terminate_build_process_group(child.id());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        for drain in output_drains {
            if let Ok((name, bytes)) = drain.join() {
                if name == "stdout" {
                    stdout = bytes;
                } else {
                    stderr = bytes;
                }
            }
        }
        let mut cleanup_error = None;
        for (target, backup, existed) in secret_mounted.into_iter().rev() {
            if target.exists() {
                if let Err(err) = fs::remove_file(&target) {
                    cleanup_error.get_or_insert(err.into());
                }
            }
            if existed {
                fs::rename(backup, target)?;
            }
        }
        for (target, backup, cache, existed, persist, lock) in mounted.into_iter().rev() {
            if target.exists() {
                if persist {
                    if let Err(err) = reject_cache_symlinks(&target) {
                        cleanup_error.get_or_insert(err);
                    } else if let Err(err) = copy_path_recursive(&target, &cache) {
                        cleanup_error.get_or_insert(err);
                    }
                }
                let _ = fs::remove_dir_all(&target);
            }
            if existed {
                fs::rename(backup, target)?;
            }
            if !persist {
                let _ = fs::remove_dir_all(cache);
            }
            drop(lock);
        }
        for (_source, target, backup, existed) in ssh_mounted.into_iter().rev() {
            let _ = fs::remove_file(&target);
            if existed {
                fs::rename(backup, target)?;
            }
        }
        for (target, existed) in tmpfs_targets.into_iter().rev() {
            if !existed {
                let _ = fs::remove_dir_all(target);
            }
        }
        for (_source, target, backup, existed, _) in bind_mounted.into_iter().rev() {
            if target.is_dir() {
                let _ = fs::remove_dir_all(&target);
            } else {
                let _ = fs::remove_file(&target);
            }
            if existed {
                fs::rename(backup, target)?;
            }
        }
        if let Some(cgroup) = run_cgroup {
            cgroup.cleanup()?;
        }
        cleanup_cgroup_mount_stub(
            cgroup_mount_target.as_deref(),
            cgroup_mount_existed,
            &rootfs,
        );
        if !proc_mount_existed {
            if let Some(target) = proc_mount_target.as_ref() {
                let _ = fs::remove_dir(target);
            }
        }
        if let Some(err) = cleanup_error {
            return Err(err);
        }
        let status = status_result?;
        if !status.success() {
            let stdout = String::from_utf8_lossy(&stdout);
            let stderr = String::from_utf8_lossy(&stderr);
            return Err(DockerfileBuildError::Invalid(format!(
                "RUN {} failed with status {status}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                run.args.join(" "),
                stdout.trim_end(),
                stderr.trim_end(),
            )));
        }
    }
    Ok(())
}

/// Give every Dockerfile RUN the daemon's outbound resolver configuration.
/// Both chroot and bubblewrap replace the host mount namespace's `/etc`, so an
/// image without its own resolv.conf would otherwise lose DNS despite having
/// an attached network.
fn provision_build_network_files(rootfs: &Path) -> Result<(), DockerfileBuildError> {
    let source = Path::new("/etc/resolv.conf");
    let bytes = fs::read(source).map_err(|error| {
        DockerfileBuildError::Invalid(format!(
            "RUN cannot read host resolver {}: {error}",
            source.display()
        ))
    })?;
    let target = rootfs.join("etc/resolv.conf");
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    if fs::symlink_metadata(&target).is_ok() {
        fs::remove_file(&target)?;
    }
    fs::write(&target, bytes)?;
    Ok(())
}

fn should_isolate_build_network(network_mode: DockerfileNetworkMode) -> bool {
    // The current sandbox executor shares the daemon network, as the rootless
    // bubblewrap path already does. `none` remains a distinct empty namespace;
    // `host` is separately entitlement-gated before execution.
    network_mode == DockerfileNetworkMode::None
}

/// Resolve a Dockerfile mount target without following symlinks in the
/// rootfs. Mount targets are build-controlled paths, so accepting a symlinked
/// component would allow a Dockerfile to redirect cache or secret material
/// outside the intended rootfs. Missing components are permitted and created
/// by the caller after this check.
fn validate_mount_target(
    rootfs: &Path,
    target: &str,
    kind: &str,
) -> Result<PathBuf, DockerfileBuildError> {
    let relative = target.strip_prefix('/').ok_or_else(|| {
        DockerfileBuildError::Invalid(format!("{kind} mount target must be absolute: {target}"))
    })?;
    let mut resolved = rootfs.to_path_buf();
    for component in Path::new(relative).components() {
        let std::path::Component::Normal(part) = component else {
            return Err(DockerfileBuildError::Invalid(format!(
                "{kind} mount target contains traversal: {target}"
            )));
        };
        resolved.push(part);
        if let Ok(metadata) = fs::symlink_metadata(&resolved) {
            if metadata.file_type().is_symlink() {
                return Err(DockerfileBuildError::Invalid(format!(
                    "{kind} mount target may not traverse a symlink: {target}"
                )));
            }
        }
    }
    Ok(resolved)
}

fn build_root_relative_path(
    rootfs: &Path,
    host_target: &Path,
) -> Result<PathBuf, DockerfileBuildError> {
    let relative = host_target.strip_prefix(rootfs).map_err(|_| {
        DockerfileBuildError::Invalid(format!(
            "build mount target escaped rootfs: {}",
            host_target.display()
        ))
    })?;
    Ok(Path::new("/").join(relative))
}

#[derive(Clone, Debug, Default)]
struct BuildLimits {
    memory_bytes: Option<u64>,
    cpu_seconds: Option<u64>,
    timeout: Option<Duration>,
    cancel_file: Option<PathBuf>,
    wall_clock: Option<Duration>,
    max_steps: Option<u64>,
    max_output_bytes: Option<u64>,
    max_parallel_stages: Option<u64>,
}

/// Default bound on concurrently executing build stages. Independent stages
/// run in parallel up to this many workers; stages beyond it queue.
const DEFAULT_MAX_PARALLEL_STAGES: usize = 4;

fn resolve_max_parallel_stages(limits: &BuildLimits) -> usize {
    limits
        .max_parallel_stages
        .map(|value| (value as usize).clamp(1, 64))
        .unwrap_or(DEFAULT_MAX_PARALLEL_STAGES)
}

fn load_build_limits() -> Result<BuildLimits, DockerfileBuildError> {
    let memory_bytes = parse_limit_env("FERROCRATE_BUILD_MEMORY_MAX")?;
    let cpu_seconds = parse_limit_env("FERROCRATE_BUILD_CPU_SECONDS")?;
    let timeout = parse_limit_env("FERROCRATE_BUILD_TIMEOUT_MS")?.map(Duration::from_millis);
    let wall_clock = parse_limit_env("FERROCRATE_BUILD_WALL_CLOCK_MS")?.map(Duration::from_millis);
    let max_steps = parse_limit_env("FERROCRATE_BUILD_MAX_STEPS")?;
    let max_output_bytes = parse_limit_env("FERROCRATE_BUILD_MAX_OUTPUT_BYTES")?;
    let max_parallel_stages = parse_limit_env("FERROCRATE_BUILD_MAX_PARALLEL_STAGES")?;
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
        wall_clock,
        max_steps,
        max_output_bytes,
        max_parallel_stages,
    })
}

/// Whole-build control state: the per-step limits plus a wall-clock deadline
/// computed once when the build starts. Shared immutably across stage workers.
#[derive(Clone, Debug)]
struct BuildControl {
    limits: BuildLimits,
    deadline: Option<Instant>,
}

impl BuildControl {
    fn load() -> Result<Self, DockerfileBuildError> {
        let limits = load_build_limits()?;
        let deadline = limits.wall_clock.map(|clock| Instant::now() + clock);
        Ok(BuildControl { limits, deadline })
    }

    /// Fail closed when the build was cancelled or exceeded its wall clock.
    /// Checked at build start, before every stage batch, and immediately
    /// before publishing the image, so a cancelled build never publishes.
    fn check(&self, phase: &str) -> Result<(), DockerfileBuildError> {
        if let Some(path) = &self.limits.cancel_file {
            if path.exists() {
                return Err(DockerfileBuildError::Cancelled(format!(
                    "cancel file {} exists at {phase}",
                    path.display()
                )));
            }
        }
        if self.deadline_exceeded() {
            return Err(DockerfileBuildError::LimitExceeded(format!(
                "wall clock exceeded at {phase}"
            )));
        }
        Ok(())
    }

    fn deadline_exceeded(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }
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

fn parse_buildkit_byte_size(name: &str, value: &str) -> Result<u64, DockerfileBuildError> {
    let split = value
        .bytes()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, suffix) = value.split_at(split);
    let base = number.parse::<u64>().map_err(|_| {
        DockerfileBuildError::Invalid(format!("{name} must be a valid byte size"))
    })?;
    if base == 0 {
        return Err(DockerfileBuildError::Invalid(format!(
            "{name} must be greater than zero"
        )));
    }
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        "t" | "tb" | "tib" => 1024_u64.pow(4),
        _ => {
            return Err(DockerfileBuildError::Invalid(format!(
                "{name} must be a valid byte size"
            )))
        }
    };
    base.checked_mul(multiplier).ok_or_else(|| {
        DockerfileBuildError::Invalid(format!("{name} byte size overflows u64"))
    })
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

fn reject_cache_path_symlinks(path: &Path) -> Result<(), DockerfileBuildError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if let Ok(metadata) = fs::symlink_metadata(&current) {
            if metadata.file_type().is_symlink() {
                return Err(DockerfileBuildError::Invalid(format!(
                    "cache mount path contains a symlink: {}",
                    current.display()
                )));
            }
        }
    }
    Ok(())
}

fn acquire_cache_lock(path: &Path) -> Result<File, DockerfileBuildError> {
    if let Some(parent) = path.parent() {
        reject_cache_path_symlinks(parent)?;
        fs::create_dir_all(parent)?;
    }
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    #[cfg(unix)]
    {
        #[allow(deprecated)]
        nix::fcntl::flock(lock.as_raw_fd(), nix::fcntl::FlockArg::LockExclusive).map_err(
            |err| {
                DockerfileBuildError::Invalid(format!(
                    "cache mount lock {} failed: {err}",
                    path.display()
                ))
            },
        )?;
    }
    #[cfg(not(unix))]
    {
        let _ = lock;
        return Err(DockerfileBuildError::Unsupported(
            "RUN cache mount sharing=locked requires a Unix host".to_string(),
        ));
    }
    Ok(lock)
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

fn setup_build_namespace_root(
    isolate_network: bool,
    isolate_cgroup: bool,
) -> io::Result<()> {
    use nix::sched::{unshare, CloneFlags};
    let mut flags = CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUTS;
    if isolate_network {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    if isolate_cgroup {
        flags |= CloneFlags::CLONE_NEWCGROUP;
    }
    unshare(flags)
        .map_err(|err| io::Error::other(err.to_string()))?;
    make_mount_namespace_private()
}

#[cfg(unix)]
fn create_build_process_group() -> io::Result<()> {
    let process = nix::unistd::Pid::from_raw(0);
    nix::unistd::setpgid(process, process).map_err(|error| io::Error::other(error.to_string()))
}

#[cfg(unix)]
fn terminate_build_process_group(leader: u32) {
    let Ok(leader) = i32::try_from(leader) else {
        return;
    };
    let _ = nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(leader),
        nix::sys::signal::Signal::SIGKILL,
    );
}

fn child_requires_cgroup_namespace(options: &DockerfileExecutionOptions) -> bool {
    options.cgroup_parent.is_some()
        || options.memory.is_some()
        || options.memory_swap.is_some()
        || options.cpu_shares.is_some()
        || options.cpu_quota.is_some()
        || options.cpu_period.is_some()
        || options.cpuset_cpus.is_some()
        || options.cpuset_mems.is_some()
        || options.pids_limit.is_some()
}

fn cleanup_cgroup_mount_stub(target: Option<&Path>, existed: bool, rootfs: &Path) {
    if existed {
        return;
    }
    let Some(target) = target else {
        return;
    };
    let _ = fs::remove_dir(target);
    for relative in ["sys/fs", "sys"] {
        let path = rootfs.join(relative);
        let _ = fs::remove_dir(path);
    }
}

#[derive(Debug)]
struct BuildRunCgroup {
    path: PathBuf,
}

impl BuildRunCgroup {
    fn cleanup(self) -> Result<(), DockerfileBuildError> {
        let kill = self.path.join("cgroup.kill");
        if kill.exists() {
            let _ = fs::write(&kill, "1\n");
        }
        fs::remove_dir(&self.path).map_err(|err| {
            DockerfileBuildError::Invalid(format!(
                "remove RUN cgroup {}: {err}",
                self.path.display()
            ))
        })
    }
}

fn prepare_build_run_cgroup(
    options: &DockerfileExecutionOptions,
    run_index: usize,
) -> Result<Option<BuildRunCgroup>, DockerfileBuildError> {
    let requested = child_requires_cgroup_namespace(options);
    if !requested {
        return Ok(None);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = run_index;
        return Err(DockerfileBuildError::Unsupported(
            "RUN resource options require a Linux cgroup v2 host".to_string(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        use crate::cgroups::{CgroupV2Manager, CpuMax, ResourceLimits};

        let root = std::env::var_os("FERROCRATE_CGROUP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup"));
        let parent = options
            .cgroup_parent
            .as_deref()
            .unwrap_or("ferrocrate-build")
            .trim_start_matches('/');
        if parent.is_empty()
            || parent.split('/').any(|part| part.is_empty() || part == "." || part == "..")
            || parent.contains('\\')
            || parent.contains('\0')
        {
            return Err(DockerfileBuildError::Invalid(format!(
                "invalid cgroup-parent {parent:?}"
            )));
        }
        let name = format!(
            "{parent}/run-{}-{run_index}",
            std::process::id()
        );
        let manager = CgroupV2Manager::new(&root);
        let path = manager.create_group(&name).map_err(|err| {
            DockerfileBuildError::Invalid(format!("create RUN cgroup {name}: {err}"))
        })?;
        let limits = ResourceLimits {
            memory_max: options.memory,
            cpu_max: options.cpu_quota.map(|quota| CpuMax {
                quota,
                period: options.cpu_period.unwrap_or(100_000),
            }),
            pids_max: options.pids_limit,
        };
        if let Err(err) = manager.apply_limits(&path, &limits) {
            let _ = fs::remove_dir(&path);
            return Err(DockerfileBuildError::Invalid(format!(
                "apply RUN cgroup limits: {err}"
            )));
        }
        let write = |name: &str, value: String| -> Result<(), DockerfileBuildError> {
            fs::write(path.join(name), value).map_err(|err| {
                DockerfileBuildError::Invalid(format!(
                    "write RUN cgroup option {}: {err}",
                    path.join(name).display()
                ))
            })
        };
        if let Some(shares) = options.cpu_shares {
            let shares = shares.clamp(2, 262_144);
            let weight = 1 + ((shares - 2) * 9_999) / 262_142;
            write("cpu.weight", weight.to_string())?;
        }
        if options.cpu_quota.is_none() {
            if let Some(period) = options.cpu_period {
                write("cpu.max", format!("max {period}"))?;
            }
        }
        if let Some(cpus) = &options.cpuset_cpus {
            write("cpuset.cpus", cpus.clone())?;
        }
        if let Some(mems) = &options.cpuset_mems {
            write("cpuset.mems", mems.clone())?;
        }
        if let Some(total) = options.memory_swap {
            let value = if total < 0 {
                "max".to_string()
            } else if let Some(memory) = options.memory {
                (total as u64).saturating_sub(memory).to_string()
            } else {
                total.to_string()
            };
            write("memory.swap.max", value)?;
        }
        Ok(Some(BuildRunCgroup { path }))
    }
}

fn apply_dockerfile_ulimits(ulimits: &[DockerfileUlimit]) -> io::Result<()> {
    for limit in ulimits {
        let resource = match limit.name.as_str() {
            "core" => nix::libc::RLIMIT_CORE,
            "cpu" => nix::libc::RLIMIT_CPU,
            "data" => nix::libc::RLIMIT_DATA,
            "fsize" => nix::libc::RLIMIT_FSIZE,
            "memlock" => nix::libc::RLIMIT_MEMLOCK,
            "nofile" => nix::libc::RLIMIT_NOFILE,
            "nproc" => nix::libc::RLIMIT_NPROC,
            "rss" => nix::libc::RLIMIT_RSS,
            "stack" => nix::libc::RLIMIT_STACK,
            #[cfg(target_os = "linux")]
            "locks" => nix::libc::RLIMIT_LOCKS,
            #[cfg(target_os = "linux")]
            "msgqueue" => nix::libc::RLIMIT_MSGQUEUE,
            #[cfg(target_os = "linux")]
            "nice" => nix::libc::RLIMIT_NICE,
            #[cfg(target_os = "linux")]
            "rtprio" => nix::libc::RLIMIT_RTPRIO,
            #[cfg(target_os = "linux")]
            "rttime" => nix::libc::RLIMIT_RTTIME,
            #[cfg(target_os = "linux")]
            "sigpending" => nix::libc::RLIMIT_SIGPENDING,
            name => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported ulimit name {name:?}"),
                ))
            }
        };
        let raw = nix::libc::rlimit {
            rlim_cur: limit.soft as nix::libc::rlim_t,
            rlim_max: limit.hard as nix::libc::rlim_t,
        };
        // SAFETY: `raw` is fully initialized and `resource` is one of libc's
        // platform constants. This runs in the child immediately before exec.
        if unsafe { nix::libc::setrlimit(resource, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Mark the freshly unshared mount namespace private. On hosts whose root
/// mount is shared (systemd default), bind mounts made inside the new
/// namespace otherwise propagate back to the parent namespace and leak
/// past the RUN's lifetime.
fn make_mount_namespace_private() -> io::Result<()> {
    use nix::mount::{mount, MsFlags};
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|err| io::Error::other(format!("make mount namespace private: {err}")))
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
            onbuild: Vec::new(),
            env: Vec::new(),
            config: BaseConfig::default(),
        });
    }

    let selector = normalize_selector(base).map_err(DockerfileBuildError::Reference)?;
    if resolve_reference(store, base)
        .map_err(DockerfileBuildError::Reference)?
        .is_none()
    {
        if matches!(selector, ImageSelector::IdPrefix(_)) {
            return Err(DockerfileBuildError::Invalid(format!(
                "base image not found locally: {base}"
            )));
        }
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
    let onbuild = load_base_onbuild_triggers(runtime_dir, &manifest.config.digest)?;
    let env = load_base_environment(runtime_dir, &manifest.config.digest)?;
    let config = load_base_config(runtime_dir, &manifest.config.digest)?;
    Ok(BaseImageInfo {
        layers,
        descriptors: manifest.layers,
        digest: Some(record.digest),
        onbuild,
        env,
        config,
    })
}

/// Read the base image's runtime config. Missing or malformed fields yield
/// defaults rather than an error: an image is still usable without them.
fn load_base_config(
    runtime_dir: &Path,
    config_digest: &str,
) -> Result<BaseConfig, DockerfileBuildError> {
    let path = config_path(runtime_dir, config_digest);
    if !path.exists() {
        return Ok(BaseConfig::default());
    }
    let bytes = fs::read(path)?;
    let document: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|err| DockerfileBuildError::Invalid(format!("base config JSON: {err}")))?;
    let Some(config) = document.get("config") else {
        return Ok(BaseConfig::default());
    };

    let strings = |key: &str| -> Option<Vec<String>> {
        config
            .get(key)
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
    };
    let text = |key: &str| -> Option<String> {
        config
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };
    let keys = |key: &str| -> Vec<String> {
        config
            .get(key)
            .and_then(serde_json::Value::as_object)
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default()
    };

    Ok(BaseConfig {
        architecture: document
            .get("architecture")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        os: document
            .get("os")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        os_version: document
            .get("os.version")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        variant: document
            .get("variant")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        entrypoint: strings("Entrypoint").filter(|values| !values.is_empty()),
        cmd: strings("Cmd").filter(|values| !values.is_empty()),
        workdir: text("WorkingDir"),
        user: text("User"),
        stop_signal: text("StopSignal"),
        exposed_ports: keys("ExposedPorts"),
        volumes: keys("Volumes"),
        labels: config
            .get("Labels")
            .and_then(serde_json::Value::as_object)
            .map(|map| {
                map.iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|text| (key.clone(), text.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default(),
    })
}

fn load_base_onbuild_triggers(
    runtime_dir: &Path,
    config_digest: &str,
) -> Result<Vec<String>, DockerfileBuildError> {
    let path = config_path(runtime_dir, config_digest);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(path)?;
    let config: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|err| DockerfileBuildError::Invalid(format!("base config JSON: {err}")))?;
    let Some(values) = config
        .get("config")
        .and_then(|value| value.get("OnBuild"))
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(Vec::new());
    };
    values
        .iter()
        .map(|value| {
            let trigger = value.as_str().ok_or_else(|| {
                DockerfileBuildError::Invalid("base OnBuild entry must be a string".to_string())
            })?;
            parse_onbuild(trigger)
        })
        .collect()
}

fn load_base_environment(
    runtime_dir: &Path,
    config_digest: &str,
) -> Result<Vec<String>, DockerfileBuildError> {
    let path = config_path(runtime_dir, config_digest);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(path)?;
    let config: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|err| DockerfileBuildError::Invalid(format!("base config JSON: {err}")))?;
    let Some(values) = config
        .get("config")
        .and_then(|value| value.get("Env"))
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(Vec::new());
    };
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|entry| entry.contains('='))
                .map(str::to_string)
                .ok_or_else(|| {
                    DockerfileBuildError::Invalid(
                        "base config Env must contain key=value strings".to_string(),
                    )
                })
        })
        .collect()
}

/// Compose base-image and Dockerfile `ENV` values. Dockerfile assignments
/// override matching base keys but preserve base PATH/toolchain values.
/// Decide a stage's entrypoint and command from its own instructions and its
/// base image's. Docker's rule: a stage that sets ENTRYPOINT drops the inherited
/// CMD unless it sets CMD too, so an inherited command cannot be handed to an
/// unrelated entrypoint.
fn inherited_command(
    stage_entrypoint: Option<&[String]>,
    stage_cmd: Option<&[String]>,
    base_entrypoint: Option<&[String]>,
    base_cmd: Option<&[String]>,
) -> (Option<Vec<String>>, Option<Vec<String>>) {
    let entrypoint = stage_entrypoint.or(base_entrypoint).map(<[String]>::to_vec);
    let cmd = match (stage_cmd, stage_entrypoint) {
        (Some(cmd), _) => Some(cmd.to_vec()),
        (None, Some(_)) => None,
        (None, None) => base_cmd.map(<[String]>::to_vec),
    };
    (entrypoint, cmd)
}

/// Base values first, then the stage's own, without duplicates.
fn merge_unique(base: &[String], stage: &[String]) -> Vec<String> {
    let mut merged: Vec<String> = Vec::new();
    for value in base.iter().chain(stage) {
        if !merged.iter().any(|existing| existing == value) {
            merged.push(value.clone());
        }
    }
    merged
}

fn stage_environment(base: &BaseImageInfo, stage: &[String]) -> Vec<String> {
    let mut env = Vec::new();
    for entry in base.env.iter().chain(stage) {
        let Some((key, _)) = entry.split_once('=') else {
            continue;
        };
        if let Some(index) = env.iter().position(|existing: &String| {
            existing
                .split_once('=')
                .is_some_and(|(existing_key, _)| existing_key == key)
        }) {
            env[index] = entry.clone();
        } else {
            env.push(entry.clone());
        }
    }
    env
}

fn apply_onbuild_triggers(
    stage: &mut StageSpec,
    triggers: &[String],
) -> Result<(), DockerfileBuildError> {
    for trigger in triggers {
        let parsed = parse_stages(&format!("FROM scratch\n{trigger}\n"))?;
        let instruction = parsed
            .first()
            .ok_or_else(|| DockerfileBuildError::Invalid("empty ONBUILD trigger".to_string()))?;
        stage.copy_from.extend(instruction.copy_from.clone());
        stage.copy_paths.extend(instruction.copy_paths.clone());
        stage.env.extend(instruction.env.clone());
        stage.args.extend(instruction.args.clone());
        stage.labels.extend(instruction.labels.clone());
        if instruction.workdir.is_some() {
            stage.workdir = instruction.workdir.clone();
        }
        if instruction.user.is_some() {
            stage.user = instruction.user.clone();
        }
        if instruction.author.is_some() {
            stage.author = instruction.author.clone();
        }
        if instruction.stop_signal.is_some() {
            stage.stop_signal = instruction.stop_signal.clone();
        }
        stage
            .exposed_ports
            .extend(instruction.exposed_ports.clone());
        stage.volumes.extend(instruction.volumes.clone());
        if instruction.entrypoint.is_some() {
            stage.entrypoint = instruction.entrypoint.clone();
        }
        if instruction.cmd.is_some() {
            stage.cmd = instruction.cmd.clone();
        }
        if instruction.healthcheck.is_some() {
            stage.healthcheck = instruction.healthcheck.clone();
        }
        stage.run.extend(instruction.run.clone());
    }
    Ok(())
}

fn resolve_stage_root(
    roots: &[PathBuf],
    names: &HashMap<String, PathBuf>,
    contexts: &HashMap<String, PathBuf>,
    from: &str,
) -> Option<PathBuf> {
    if let Ok(idx) = from.parse::<usize>() {
        return roots.get(idx).cloned();
    }
    names
        .get(from)
        .cloned()
        .or_else(|| contexts.get(from).cloned())
}

fn safe_context_source(root: &Path, source: &str) -> Result<PathBuf, DockerfileBuildError> {
    let relative = Path::new(source.trim_start_matches('/'));
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(DockerfileBuildError::Invalid(
            "COPY --from source escapes its context".to_string(),
        ));
    }
    let candidate = root.join(relative);
    let canonical = fs::canonicalize(&candidate).map_err(|error| {
        DockerfileBuildError::Invalid(format!("COPY --from source is unavailable: {error}"))
    })?;
    if !canonical.starts_with(root) {
        return Err(DockerfileBuildError::Invalid(
            "COPY --from source escapes its context".to_string(),
        ));
    }
    Ok(canonical)
}

fn safe_context_destination(
    root: &Path,
    destination: &str,
) -> Result<PathBuf, DockerfileBuildError> {
    let relative = Path::new(destination.trim_start_matches('/'));
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(DockerfileBuildError::Invalid(
            "COPY destination escapes the build context".to_string(),
        ));
    }
    Ok(root.join(relative))
}

fn create_build_dir(runtime_dir: &Path, name: &str) -> Result<PathBuf, DockerfileBuildError> {
    // Keep build scratch state under the caller's runtime directory. A global
    // `/tmp/ferrocrate-build` root can be left owned by a privileged daemon and
    // then make an otherwise unprivileged Docker-compatible build fail with
    // EACCES. Per-runtime allocation also prevents concurrent daemons from
    // sharing build context names or cleanup state.
    let root = runtime_dir.join("build");
    fs::create_dir_all(&root)?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0..16u32 {
        let candidate = root.join(format!(
            "{}-{}-{}-{}",
            name,
            std::process::id(),
            nanos,
            attempt
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(DockerfileBuildError::Invalid(
        "could not allocate a unique build directory".to_string(),
    ))
}

fn copy_context_dir(
    root: &Path,
    src: &Path,
    dst: &Path,
    dockerfile_path: &Path,
    ignore_patterns: &[String],
) -> Result<(), DockerfileBuildError> {
    fs::create_dir_all(dst)?;
    // `DirEntry::path()` preserves the spelling of the source path.  When a
    // relative context is used, a lexical `Path::starts_with` comparison can
    // miss that the destination is inside the source tree.  Canonicalize the
    // already-created destination once per recursion level so the exclusion
    // remains correct for both relative and absolute callers.
    let canonical_dst = fs::canonicalize(dst)?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(src)? {
        entries.push(entry?);
    }
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        // A caller may place its runtime directory inside the Dockerfile
        // context (common in tests and valid for local CLI workflows). Build
        // scratch now lives under that runtime directory, so do not recurse
        // back into the destination while copying the source context.
        if canonical_dst.starts_with(fs::canonicalize(&path).unwrap_or_else(|_| path.to_path_buf()))
        {
            continue;
        }
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
            fs::create_dir_all(&target)?;
            // `relative` is always rooted at the original context; keep the
            // destination rooted there too. Passing `target` here duplicates
            // every nested component (a/b becomes a/a/b).
            copy_context_dir(root, &path, dst, dockerfile_path, ignore_patterns)?;
        } else if file_type.is_symlink() {
            copy_symlink(&path, &target)?;
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
    let remote_root = tempfile::tempdir()?;
    for spec in copies {
        let dest_root = dst_root.join(spec.dest.trim_start_matches('/'));
        if let Some(content) = spec.inline_content.as_deref() {
            if spec.dest.ends_with('/') {
                return Err(DockerfileBuildError::Invalid(
                    "COPY heredoc destination must name a file".to_string(),
                ));
            }
            if let Some(parent) = dest_root.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&dest_root, content)?;
            if let Some(mode) = spec.chmod {
                #[cfg(unix)]
                fs::set_permissions(&dest_root, fs::Permissions::from_mode(mode))?;
            }
            continue;
        }
        let sources = expand_copy_sources(src_root, &spec.srcs)?;
        let multiple = sources.len() > 1 || spec.dest.ends_with('/');
        if multiple {
            fs::create_dir_all(&dest_root)?;
        }
        for src in &sources {
            if spec.parents
                && Path::new(src)
                    .components()
                    .any(|component| component == std::path::Component::ParentDir)
            {
                return Err(DockerfileBuildError::Invalid(
                    "COPY --parents source must not contain parent traversal".to_string(),
                ));
            }
            // An explicitly named source starts recursion with an empty
            // relative path, so apply excludes to that source before entering
            // the recursive walker. Without this check, `COPY --exclude=foo
            // foo /dest` would incorrectly materialize `foo`.
            if copy_path_is_excluded(Path::new(src.trim_start_matches('/')), &spec.excludes) {
                continue;
            }
            let (source, source_name) = if spec.extract_archives && is_remote_add_source(src) {
                let downloaded = download_add_source(src, remote_root.path())?;
                if let Some(expected) = spec.checksum.as_ref() {
                    let expected = format!("sha256:{expected}");
                    if !file_matches_digest(&downloaded, &expected) {
                        return Err(DockerfileBuildError::Invalid(format!(
                            "ADD --checksum mismatch for {src}"
                        )));
                    }
                }
                (downloaded, remote_add_source_name(src))
            } else {
                if spec.checksum.is_some() {
                    return Err(DockerfileBuildError::Invalid(
                        "ADD --checksum requires a remote HTTP(S) source".to_string(),
                    ));
                }
                (
                    src_root.join(src.trim_start_matches('/')),
                    Path::new(src)
                        .file_name()
                        .map(|name| name.to_string_lossy().to_string())
                        .unwrap_or_else(|| "src".to_string()),
                )
            };
            fs::symlink_metadata(&source).map_err(|error| {
                DockerfileBuildError::Invalid(format!(
                    "COPY source {} is unavailable: {error}",
                    source.display()
                ))
            })?;
            // Docker copies a directory source's contents, regardless of
            // whether the source spelling has a trailing slash. `.` names
            // the build context itself, so `WORKDIR /src` + `COPY . .` must
            // place Cargo.toml at /src; likewise `COPY frontend ./` must
            // put frontend's files directly in the WORKDIR rather than
            // creating a nested frontend/frontend directory.
            let copy_contents = source.is_dir();
            let dest = if copy_contents {
                dest_root.clone()
            } else if spec.parents {
                dest_root.join(src.trim_start_matches('/'))
            } else if multiple {
                dest_root.join(source_name)
            } else {
                dest_root.clone()
            };
            if copy_contents {
                for entry in fs::read_dir(&source)? {
                    let entry = entry?;
                    let name = entry.file_name();
                    copy_path_recursive_mode_with_excludes(
                        &entry.path(),
                        &dest_root.join(&name),
                        spec.chmod,
                        &spec.excludes,
                        Path::new(&name),
                    )?;
                }
                continue;
            }
            let archive_dest = if spec.extract_archives {
                &dest_root
            } else {
                &dest
            };
            if spec.extract_archives
                && extract_add_archive(&source, archive_dest, spec.chmod, &spec.excludes)?
            {
                if let Some(owner) = spec.owner.as_ref() {
                    apply_copy_owner_recursive(archive_dest, owner)?;
                }
                continue;
            }
            copy_path_recursive_mode_with_excludes(
                &source,
                &dest,
                spec.chmod,
                &spec.excludes,
                Path::new(""),
            )?;
            if let Some(owner) = spec.owner.as_ref() {
                apply_copy_owner_recursive(&dest, owner)?;
            }
        }
    }
    Ok(())
}

/// Expand Dockerfile COPY/ADD source globs against the build context.  This
/// deliberately does not use the process shell: context paths stay confined
/// to `src_root`, and an empty expansion remains a Dockerfile error.
fn expand_copy_sources(
    src_root: &Path,
    sources: &[String],
) -> Result<Vec<String>, DockerfileBuildError> {
    let mut expanded = Vec::new();
    for source in sources {
        if is_remote_add_source(source) || !source.contains(['*', '?', '[']) {
            expanded.push(source.clone());
            continue;
        }
        let relative = Path::new(source.trim_start_matches('/'));
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| component == std::path::Component::ParentDir)
        {
            return Err(DockerfileBuildError::Invalid(
                "COPY source escapes the build context".to_string(),
            ));
        }
        let mut matches = Vec::new();
        collect_copy_glob_matches(
            src_root,
            src_root,
            source.trim_start_matches('/'),
            &mut matches,
        )?;
        matches.sort();
        if matches.is_empty() {
            return Err(DockerfileBuildError::Invalid(format!(
                "COPY source {} is unavailable: glob matched no files",
                src_root.join(source).display()
            )));
        }
        expanded.extend(matches);
    }
    Ok(expanded)
}

fn collect_copy_glob_matches(
    root: &Path,
    directory: &Path,
    pattern: &str,
    matches: &mut Vec<String>,
) -> Result<(), DockerfileBuildError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .expect("context walk stays under root")
            .to_string_lossy()
            .replace('\\', "/");
        if copy_glob_matches(pattern, &relative) {
            matches.push(relative.clone());
        }
        if entry.file_type()?.is_dir() {
            collect_copy_glob_matches(root, &path, pattern, matches)?;
        }
    }
    Ok(())
}

/// Match the shell glob subset Docker accepts for context sources. `*` and
/// `?` do not cross directory separators, matching filepath-style patterns.
fn copy_glob_matches(pattern: &str, value: &str) -> bool {
    fn matches(pattern: &[u8], value: &[u8]) -> bool {
        match pattern {
            [] => value.is_empty(),
            [b'*', rest @ ..] => {
                matches(rest, value)
                    || (!value.is_empty() && value[0] != b'/' && matches(pattern, &value[1..]))
            }
            [b'?', rest @ ..] => {
                !value.is_empty() && value[0] != b'/' && matches(rest, &value[1..])
            }
            [byte, rest @ ..] => {
                !value.is_empty() && *byte == value[0] && matches(rest, &value[1..])
            }
        }
    }
    matches(pattern.as_bytes(), value.as_bytes())
}

fn resolve_copy_owner(
    rootfs: &Path,
    owner: &CopyOwner,
) -> Result<(u32, u32), DockerfileBuildError> {
    let CopyOwner::Named { user, group } = owner else {
        let CopyOwner::Numeric(uid, gid) = owner else {
            unreachable!();
        };
        return Ok((*uid, *gid));
    };
    let passwd = fs::read_to_string(rootfs.join("etc/passwd")).map_err(|error| {
        DockerfileBuildError::Invalid(format!(
            "COPY --chown user {user} cannot be resolved from base image: {error}"
        ))
    })?;
    let entry = passwd
        .lines()
        .find_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            (fields.len() >= 4 && fields[0] == user).then(|| {
                Some((
                    fields[2].parse::<u32>().ok()?,
                    fields[3].parse::<u32>().ok()?,
                ))
            })
        })
        .flatten()
        .ok_or_else(|| {
            DockerfileBuildError::Invalid(format!(
                "COPY --chown user {user} is not present in the base image"
            ))
        })?;
    let gid = match group {
        None => entry.1,
        Some(value) => {
            if let Ok(gid) = value.parse::<u32>() {
                gid
            } else {
                let groups = fs::read_to_string(rootfs.join("etc/group")).map_err(|error| {
                    DockerfileBuildError::Invalid(format!(
                        "COPY --chown group {value} cannot be resolved from base image: {error}"
                    ))
                })?;
                groups
                    .lines()
                    .find_map(|line| {
                        let fields = line.split(':').collect::<Vec<_>>();
                        (fields.len() >= 3 && fields[0] == value)
                            .then(|| fields[2].parse::<u32>().ok())
                            .flatten()
                    })
                    .ok_or_else(|| {
                        DockerfileBuildError::Invalid(format!(
                            "COPY --chown group {value} is not present in the base image"
                        ))
                    })?
            }
        }
    };
    Ok((entry.0, gid))
}

fn apply_copy_owner_recursive(path: &Path, owner: &CopyOwner) -> Result<(), DockerfileBuildError> {
    #[cfg(unix)]
    {
        use nix::unistd::{chown, Gid, Uid};
        let CopyOwner::Numeric(uid, gid) = owner else {
            return Err(DockerfileBuildError::Invalid(
                "COPY --chown owner was not resolved against the base image".to_string(),
            ));
        };
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(DockerfileBuildError::Invalid(format!(
                "COPY --chown refuses symlink entry: {}",
                path.display()
            )));
        }
        chown(path, Some(Uid::from_raw(*uid)), Some(Gid::from_raw(*gid))).map_err(|error| {
            DockerfileBuildError::Invalid(format!(
                "COPY --chown cannot set {}:{} on {}: {error}",
                uid,
                gid,
                path.display()
            ))
        })?;
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                apply_copy_owner_recursive(&entry?.path(), owner)?;
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, owner);
        Err(DockerfileBuildError::Unsupported(
            "COPY --chown requires a Unix filesystem".to_string(),
        ))
    }
}

fn is_remote_add_source(source: &str) -> bool {
    matches!(reqwest::Url::parse(source), Ok(url) if matches!(url.scheme(), "http" | "https"))
}

fn remote_add_source_name(source: &str) -> String {
    reqwest::Url::parse(source)
        .ok()
        .and_then(|url| {
            url.path_segments().and_then(|mut segments| {
                segments
                    .rfind(|segment| !segment.is_empty())
                    .map(str::to_string)
            })
        })
        .filter(|name| !name.is_empty() && name != "." && name != "..")
        .unwrap_or_else(|| "download".to_string())
}

fn download_add_source(source: &str, destination: &Path) -> Result<PathBuf, DockerfileBuildError> {
    let url = reqwest::Url::parse(source).map_err(|error| {
        DockerfileBuildError::Invalid(format!("ADD remote source is not a valid URL: {error}"))
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(DockerfileBuildError::Invalid(
            "ADD remote source requires an http or https URL with a host".to_string(),
        ));
    }
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
        return Err(DockerfileBuildError::Invalid(
            "ADD remote source must not contain credentials or a fragment".to_string(),
        ));
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;
    let response = client.get(url.clone()).send()?;
    if !response.status().is_success() {
        return Err(DockerfileBuildError::Invalid(format!(
            "ADD remote source returned HTTP {}",
            response.status()
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ADD_REMOTE_SIZE)
    {
        return Err(DockerfileBuildError::Invalid(format!(
            "ADD remote source exceeds {} byte limit",
            MAX_ADD_REMOTE_SIZE
        )));
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_ADD_REMOTE_SIZE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ADD_REMOTE_SIZE {
        return Err(DockerfileBuildError::Invalid(format!(
            "ADD remote source exceeds {} byte limit",
            MAX_ADD_REMOTE_SIZE
        )));
    }
    fs::create_dir_all(destination)?;
    let digest = sha256_digest_bytes(source.as_bytes()).replace(':', "-");
    let path = destination.join(format!("{digest}-download"));
    fs::write(&path, bytes)?;
    Ok(path)
}

/// Extract a local tar or gzip-compressed tar for Dockerfile `ADD`.
///
/// Returns `false` for ordinary files, preserving Docker's copy behavior. The
/// archive path is validated before extraction and links/special files are
/// rejected so a build context cannot escape the destination root.
fn extract_add_archive(
    source: &Path,
    destination: &Path,
    chmod: Option<u32>,
    excludes: &[String],
) -> Result<bool, DockerfileBuildError> {
    let mut probe = File::open(source)?;
    let mut header = [0_u8; 512];
    let read = probe.read(&mut header)?;
    let gzip = read >= 2 && header[..2] == [0x1f, 0x8b];
    let bzip = read >= 3 && &header[..3] == b"BZh";
    let xz = read >= 6 && &header[..6] == b"\xfd7zXZ\0";
    let plain_tar = read >= 262 && &header[257..262] == b"ustar";
    if !gzip && !bzip && !xz && !plain_tar {
        return Ok(false);
    }
    fs::create_dir_all(destination)?;
    if gzip {
        extract_add_tar(
            GzDecoder::new(File::open(source)?),
            destination,
            chmod,
            excludes,
        )?;
    } else if bzip {
        extract_add_tar(
            BzDecoder::new(File::open(source)?),
            destination,
            chmod,
            excludes,
        )?;
    } else if xz {
        extract_add_tar(
            XzReader::new(File::open(source)?, true),
            destination,
            chmod,
            excludes,
        )?;
    } else {
        extract_add_tar(File::open(source)?, destination, chmod, excludes)?;
    }
    Ok(true)
}

fn extract_add_tar<R: Read>(
    reader: R,
    destination: &Path,
    chmod: Option<u32>,
    excludes: &[String],
) -> Result<(), DockerfileBuildError> {
    let mut archive = Archive::new(reader);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let relative = entry.path()?.into_owned();
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| component == std::path::Component::ParentDir)
        {
            return Err(DockerfileBuildError::Invalid(
                "ADD archive entry escapes destination".to_string(),
            ));
        }
        if copy_path_is_excluded(&relative, excludes) {
            continue;
        }
        let target = destination.join(&relative);
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            fs::create_dir_all(&target)?;
            if let Some(mode) = chmod {
                apply_copy_mode(&target, mode)?;
            }
        } else if entry_type.is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            entry.unpack(&target)?;
            if let Some(mode) = chmod {
                apply_copy_mode(&target, mode)?;
            }
        } else {
            return Err(DockerfileBuildError::Unsupported(format!(
                "ADD archive entry type is unsupported: {}",
                relative.display()
            )));
        }
    }
    Ok(())
}

/// Seed a named-stage `FROM` root with the parent stage's *contents*.
/// Copying the directory itself would introduce an extra `stage-N` path and
/// make the stage's runtime tools invisible to RUN.
fn copy_rootfs_contents(src: &Path, dst: &Path) -> Result<(), DockerfileBuildError> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        copy_path_recursive(&entry.path(), &dst.join(entry.file_name()))?;
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
    copy_path_recursive_mode_with_excludes(src, dst, chmod, &[], Path::new(""))
}

fn copy_path_recursive_mode_with_excludes(
    src: &Path,
    dst: &Path,
    chmod: Option<u32>,
    excludes: &[String],
    relative: &Path,
) -> Result<(), DockerfileBuildError> {
    if !relative.as_os_str().is_empty() && copy_path_is_excluded(relative, excludes) {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(src)?;
    if metadata.file_type().is_symlink() {
        copy_symlink(src, dst)?;
    } else if metadata.is_dir() {
        fs::create_dir_all(dst)?;
        // The runtime/build scratch directory can be nested inside the build
        // context.  Exclude that destination subtree while walking the
        // source, otherwise `COPY . /` recursively copies its own output.
        let canonical_dst = fs::canonicalize(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let path = entry.path();
            if canonical_dst
                .starts_with(fs::canonicalize(&path).unwrap_or_else(|_| path.to_path_buf()))
            {
                continue;
            }
            let name = entry.file_name();
            copy_path_recursive_mode_with_excludes(
                &path,
                &dst.join(&name),
                chmod,
                excludes,
                &relative.join(name),
            )?;
        }
    } else if metadata.is_file() {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(src, dst)?;
    } else {
        return Err(DockerfileBuildError::Unsupported(format!(
            "COPY source has unsupported file type: {}",
            src.display()
        )));
    }
    if let Some(mode) = chmod {
        apply_copy_mode(dst, mode)?;
    }
    Ok(())
}

#[cfg(unix)]
fn copy_symlink(src: &Path, dst: &Path) -> Result<(), DockerfileBuildError> {
    let target = fs::read_link(src).map_err(|error| {
        DockerfileBuildError::Invalid(format!(
            "COPY cannot read symlink {}: {error}",
            src.display()
        ))
    })?;
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    if fs::symlink_metadata(dst).is_ok() {
        fs::remove_file(dst)?;
    }
    std::os::unix::fs::symlink(target, dst).map_err(DockerfileBuildError::Io)
}

#[cfg(not(unix))]
fn copy_symlink(src: &Path, _dst: &Path) -> Result<(), DockerfileBuildError> {
    Err(DockerfileBuildError::Unsupported(format!(
        "COPY symlink preservation requires a Unix filesystem: {}",
        src.display()
    )))
}

fn copy_path_is_excluded(relative: &Path, patterns: &[String]) -> bool {
    let path = relative.to_string_lossy();
    let basename = relative
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    patterns.iter().any(|pattern| {
        dockerignore_matches(pattern, &path)
            || basename
                .as_deref()
                .is_some_and(|name| dockerignore_matches(pattern, name))
    })
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
    #[test]
    fn a_stage_inherits_the_base_command_and_docker_s_entrypoint_rule() {
        let base_entry = vec!["/docker-entrypoint.sh".to_string()];
        let base_cmd = vec!["nginx".to_string(), "-g".to_string()];

        // S24: a Dockerfile that only COPYs inherits both.
        assert_eq!(
            super::inherited_command(None, None, Some(&base_entry), Some(&base_cmd)),
            (Some(base_entry.clone()), Some(base_cmd.clone()))
        );

        // Setting ENTRYPOINT alone drops the inherited CMD.
        let own_entry = vec!["/app/run".to_string()];
        assert_eq!(
            super::inherited_command(Some(&own_entry), None, Some(&base_entry), Some(&base_cmd)),
            (Some(own_entry.clone()), None)
        );

        // Setting both keeps both.
        let own_cmd = vec!["--serve".to_string()];
        assert_eq!(
            super::inherited_command(
                Some(&own_entry),
                Some(&own_cmd),
                Some(&base_entry),
                Some(&base_cmd)
            ),
            (Some(own_entry), Some(own_cmd.clone()))
        );

        // CMD alone overrides the inherited command, entrypoint still inherited.
        assert_eq!(
            super::inherited_command(None, Some(&own_cmd), Some(&base_entry), Some(&base_cmd)),
            (Some(base_entry), Some(own_cmd))
        );
    }

    #[test]
    fn merge_unique_keeps_base_order_and_drops_duplicates() {
        assert_eq!(
            super::merge_unique(
                &["80/tcp".to_string(), "443/tcp".to_string()],
                &["443/tcp".to_string(), "8080/tcp".to_string()]
            ),
            vec![
                "80/tcp".to_string(),
                "443/tcp".to_string(),
                "8080/tcp".to_string()
            ]
        );
    }

    #[test]
    fn run_layer_contains_only_changed_paths_and_whiteouts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin/sh"), "base shell").unwrap();
        std::fs::write(root.join("removed"), "base file").unwrap();
        let before = super::snapshot_stage_root(&root).unwrap();
        std::fs::write(root.join("marker"), "changed").unwrap();
        std::fs::remove_file(root.join("removed")).unwrap();

        let layer = temp.path().join("layer.gz");
        super::build_layer_from_snapshot_to_file(
            &root,
            &before,
            crate::layer_compression::CompressionFormat::Gzip,
            &layer,
            None,
        )
        .unwrap();
        let decoder = flate2::read::GzDecoder::new(std::fs::File::open(layer).unwrap());
        let mut archive = tar::Archive::new(decoder);
        let names = archive
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().into_owned())
            .collect::<Vec<_>>();
        assert!(names.contains(&std::path::PathBuf::from("marker")));
        assert!(names.contains(&std::path::PathBuf::from(".wh.removed")));
        assert!(!names.contains(&std::path::PathBuf::from("bin/sh")));
    }

    #[test]
    fn run_layer_whiteouts_a_removed_directory_once_and_removes_it_when_applied() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("removed/nested")).unwrap();
        std::fs::write(root.join("removed/nested/base-file"), "base").unwrap();
        let before = super::snapshot_stage_root(&root).unwrap();
        std::fs::remove_dir_all(root.join("removed")).unwrap();

        let layer = temp.path().join("layer.gz");
        super::build_layer_from_snapshot_to_file(
            &root,
            &before,
            crate::layer_compression::CompressionFormat::Gzip,
            &layer,
            None,
        )
        .unwrap();

        let decoder = flate2::read::GzDecoder::new(std::fs::File::open(&layer).unwrap());
        let mut archive = tar::Archive::new(decoder);
        let names = archive
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, vec![std::path::PathBuf::from(".wh.removed")]);

        let runtime_root = temp.path().join("runtime-root");
        std::fs::create_dir_all(runtime_root.join("removed/nested")).unwrap();
        std::fs::write(runtime_root.join("removed/nested/base-file"), "base").unwrap();
        crate::rootfs::apply_layer_tar(&runtime_root, &layer).unwrap();
        assert!(!runtime_root.join("removed").exists());
    }

    #[test]
    fn build_journal_retains_failure_output_larger_than_one_mebibyte() {
        let temp = tempfile::tempdir().unwrap();
        let output = "maven-checkstyle-output\n".repeat(60_000);
        assert!(output.len() > 1024 * 1024);
        let journal = super::BuildJournal {
            cache_key: "cache".to_string(),
            context_digest: "context".to_string(),
            dockerfile_digest: "dockerfile".to_string(),
            base_digests: Vec::new(),
            image_reference: "local/failure:latest".to_string(),
            authorization_plan_digest: None,
            state: super::BuildJournalState::Failed,
            completed_stages: Vec::new(),
            failure_output: Some(output.clone()),
        };
        super::save_build_journal(temp.path(), &journal).unwrap();
        assert_eq!(
            super::load_build_journal(temp.path())
                .unwrap()
                .unwrap()
                .failure_output,
            Some(output)
        );
    }

    use super::{
        apply_onbuild_triggers, build_cache_key, build_cache_path,
        build_from_dockerfile_with_store_and_compression,
        build_journal_path,
        build_stage_dependency_graph, build_stage_execution_batches, create_build_dir,
        dockerfile_external_base_images, dockerignore_matches, export_build_cache,
        export_build_cache_to_registry, file_matches_digest, hash_context_dir, import_build_cache,
        import_build_cache_from_registry, layer_blob_path, load_build_cache, load_build_journal,
        load_stage_checkpoints, parse_env, parse_exposed_ports, parse_healthcheck, parse_labels,
        parse_limit_value, parse_maintainer, parse_onbuild, parse_run,
        parse_stages, parse_stages_with_build_args, parse_stop_signal, prepare_dockerfile_build,
        prepare_dockerfile_build_with_contexts,
        prepare_dockerfile_build_with_contexts_and_build_args, prune_build_cache, registry_cache_descriptor,
        registry_cache_reference, reject_cache_path_symlinks, resolve_base_image,
        resolve_copy_owner,
        run_stage_worker_pool, save_build_cache, save_build_journal, sha256_digest_bytes,
        stage_checkpoint_path, stage_content_identities, validate_mount_target, BaseImageInfo,
        BuildCacheEntry, BuildControl, BuildJournalState, BuildLimits, CacheSharing, CopyOwner,
        DockerfileBuildError, BUILD_CACHE_PLATFORM, OCI_IMAGE_LAYER_MEDIA_TYPE,
        REGISTRY_CACHE_KIND_ANNOTATION,
    };
    use sha2::Digest;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn dockerfile_external_bases_exclude_scratch_and_prior_stage_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let dockerfile = temp.path().join("Dockerfile");
        std::fs::write(
            &dockerfile,
            "FROM alpine:3.20 AS base\nFROM base AS packaged\nFROM registry.example/app:1\n",
        )
        .unwrap();

        assert_eq!(
            dockerfile_external_base_images(&dockerfile).unwrap(),
            vec!["alpine:3.20", "registry.example/app:1"]
        );
    }

    #[test]
    fn dockerfile_external_copy_images_exclude_stages_and_indexes() {
        let temp = tempfile::tempdir().unwrap();
        let dockerfile = temp.path().join("Dockerfile");
        std::fs::write(
            &dockerfile,
            "FROM scratch AS base\nCOPY --from=tonistiigi/hellofs /hellofs /bin/hellofs\nCOPY --from=base /x /x\nCOPY --from=0 /y /y\n",
        )
        .unwrap();

        assert_eq!(
            super::dockerfile_external_copy_images_with_build_args(
                &dockerfile,
                &HashMap::new()
            )
            .unwrap(),
            vec!["tonistiigi/hellofs"]
        );
    }

    #[test]
    fn from_platform_automatic_args_expand_and_unknown_args_fail_early() {
        let valid = parse_stages("FROM --platform=$BUILDPLATFORM scratch\n").unwrap();
        assert_eq!(valid[0].base, "scratch");
        let error = parse_stages("FROM --platform=$BUILPLATFORM scratch\n").unwrap_err();
        assert!(error.to_string().contains("undeclared build argument: BUILPLATFORM"));
    }

    #[test]
    fn automatic_platform_args_include_variants_and_os_versions() {
        let args = super::automatic_platform_args();
        for name in [
            "BUILDPLATFORM",
            "BUILDOS",
            "BUILDOSVERSION",
            "BUILDARCH",
            "BUILDVARIANT",
            "TARGETPLATFORM",
            "TARGETOS",
            "TARGETOSVERSION",
            "TARGETARCH",
            "TARGETVARIANT",
        ] {
            assert!(args.contains_key(name), "missing BuildKit automatic arg {name}");
        }
        assert_eq!(args["BUILDVARIANT"], "");
        assert_eq!(args["TARGETVARIANT"], "");
        assert_eq!(args["BUILDOSVERSION"], "");
        assert_eq!(args["TARGETOSVERSION"], "");
    }

    #[test]
    fn requested_platform_binds_target_args_with_os_version_and_variant() {
        let args = super::automatic_platform_args_for_target(
            Some("windows(10.0.20348.1006)/arm64/v8"),
        )
        .expect("BuildKit platform syntax parses");

        assert_eq!(args["TARGETPLATFORM"], "windows(10.0.20348.1006)/arm64/v8");
        assert_eq!(args["TARGETOS"], "windows");
        assert_eq!(args["TARGETOSVERSION"], "10.0.20348.1006");
        assert_eq!(args["TARGETARCH"], "arm64");
        assert_eq!(args["TARGETVARIANT"], "v8");
        assert_eq!(args["BUILDOS"], "linux");
        assert_eq!(args["BUILDOSVERSION"], "");
    }

    #[test]
    fn target_without_os_version_preserves_matching_base_os_version() {
        let base = super::BaseConfig {
            architecture: Some("amd64".to_string()),
            os: Some("windows".to_string()),
            os_version: Some("10.0.20348.1006".to_string()),
            variant: None,
            ..Default::default()
        };

        let output = super::output_platform_for_config(Some("windows/amd64"), &base)
            .expect("output platform");

        assert_eq!(output.os, "windows");
        assert_eq!(output.architecture, "amd64");
        assert_eq!(output.os_version, "10.0.20348.1006");
    }

    #[test]
    fn requested_platform_args_drive_from_and_stage_arg_expansion() {
        let mut args = super::automatic_platform_args_for_target(Some("darwin/ppc64le"))
            .expect("target platform");
        args.insert("TARGETOS".to_string(), "freebsd".to_string());
        let stages = parse_stages_with_build_args(
            "FROM scratch AS base-freebsd\nFROM base-${TARGETOS}\nARG TARGETPLATFORM\nARG TARGETOS\nRUN echo $TARGETPLATFORM $TARGETOS\n",
            &args,
        )
        .expect("automatic args are BuildKit expressions");

        assert_eq!(stages[1].base, "base-freebsd");
        assert_eq!(
            stages[1].run[0].args.last().map(String::as_str),
            Some("echo darwin/ppc64le freebsd")
        );
    }

    #[test]
    fn heredoc_bodies_stay_with_run_copy_and_onbuild_instructions() {
        let stages = parse_stages(
            "FROM scratch\nRUN <<-EOF\n\t#!/bin/sh\n\techo ok\n\tEOF\nCOPY <<EOF /message\nhello $name \"quotes\"\nEOF\nONBUILD RUN <<EOF\necho later\nEOF\n",
        )
        .expect("heredoc Dockerfile parses");
        assert_eq!(stages[0].run[0].args.last().unwrap(), "#!/bin/sh\necho ok");
        assert_eq!(stages[0].copy_paths[0].inline_content.as_deref(), Some("hello  \"quotes\""));
        assert_eq!(stages[0].onbuild[0], "RUN <<EOF\necho later");
    }

    #[test]
    fn copy_heredoc_build_materializes_its_body() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\nCOPY <<EOF /message\nhello\nEOF\n").unwrap();
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).unwrap();
        build_from_dockerfile_with_store_and_compression(
            &dockerfile, Some("local/copy-heredoc:latest"), &runtime,
            CompressionFormat::Gzip, &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        ).expect("COPY heredoc build");
        assert_eq!(fs::read_to_string(stage_root(&runtime, 0).join("message")).unwrap(), "hello");
    }

    #[test]
    fn uppercase_missing_id_base_fails_locally_before_pull_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).unwrap();
        let error = resolve_base_image(
            &store,
            &runtime,
            "sha256:DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("base image not found locally"));
        assert!(!error.to_string().contains("registry"));
    }

    #[test]
    fn build_scratch_is_scoped_to_runtime_directory() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();

        let scratch = create_build_dir(&runtime, "context").unwrap();

        assert!(scratch.starts_with(runtime.join("build")));
        assert!(scratch.is_dir());
    }

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
        assert_eq!(first.stage_dependencies(), &[Vec::<usize>::new()]);
        assert_eq!(first.canonical_tag(), "registry-1.docker.io/local/app:test");
        assert!(store.list_references().unwrap().is_empty());
        assert!(!runtime.join("build-cache.json").exists());
    }

    #[test]
    fn env_and_label_preserve_quoted_values_and_reject_unterminated_quotes() {
        let env = parse_env(r#"APP_NAME=ferro MODE="fast build" PATH_ESCAPED=hello\ world"#)
            .expect("quoted ENV values parse");
        assert_eq!(
            env,
            [
                "APP_NAME=ferro",
                "MODE=fast build",
                "PATH_ESCAPED=hello world"
            ]
        );

        let labels = parse_labels(r#"org.example.title="Ferro Crate" org.example.kind=runtime"#)
            .expect("quoted LABEL values parse");
        assert_eq!(
            labels.get("org.example.title"),
            Some(&"Ferro Crate".to_string())
        );
        assert_eq!(labels.get("org.example.kind"), Some(&"runtime".to_string()));

        let error = parse_env("BROKEN=\"unterminated").expect_err("unterminated quote");
        assert!(error.to_string().contains("unterminated quotes"));
        let error = parse_labels("=missing-key").expect_err("empty label key");
        assert!(error.to_string().contains("key must not be empty"));
    }

    #[test]
    fn workdir_resolves_relative_paths_cumulatively_and_rejects_root_escape() {
        let stages =
            parse_stages("FROM scratch\nWORKDIR /opt/app\nWORKDIR build\nWORKDIR ../release\n")
                .expect("relative WORKDIRs resolve");
        assert_eq!(stages[0].workdir.as_deref(), Some("/opt/app/release"));

        let error = parse_stages("FROM scratch\nWORKDIR ../../escape\n")
            .expect_err("WORKDIR must not escape image root");
        assert!(error.to_string().contains("escapes the image root"));
    }

    #[test]
    fn run_mount_targets_resolve_relative_to_stage_workdir_and_reject_parent_escapes() {
        let stages = parse_stages(
            "FROM scratch\nWORKDIR /usr/src/app\nRUN --mount=type=bind,source=package.json,target=package.json --mount=type=cache,target=.cache echo value\n",
        )
        .expect("relative bind and cache targets resolve through Dockerfile stage parsing");
        let run = &stages[0].run[0];
        assert_eq!(run.bind_mounts[0].target, "/usr/src/app/package.json");
        assert_eq!(run.cache_mounts[0].target, "/usr/src/app/.cache");

        for mount in [
            "type=bind,source=package.json,target=../package.json",
            "type=cache,target=../cache",
        ] {
            let error = parse_stages(&format!(
                "FROM scratch\nWORKDIR /usr/src/app\nRUN --mount={mount} echo value\n"
            ))
            .expect_err("RUN mount target must not escape its workdir");
            assert!(error.to_string().contains("parent traversal"));
        }
    }

    #[test]
    fn healthcheck_rejects_malformed_flags_and_empty_commands() {
        let health = parse_healthcheck(
            "--interval=2s --timeout=500ms --retries=4 --start-period=1s --start-interval=250ms CMD-SHELL curl -f http://localhost",
        )
        .expect("valid healthcheck parses")
        .expect("healthcheck is enabled");
        assert_eq!(health.interval_nanos, 2_000_000_000);
        assert_eq!(health.timeout_nanos, 500_000_000);
        assert_eq!(health.retries, 4);
        assert_eq!(health.start_period_nanos, 1_000_000_000);
        assert_eq!(health.start_interval_nanos, 250_000_000);

        for input in [
            "--interval=wat CMD-SHELL true",
            "--retries=0 CMD-SHELL true",
            "--unknown=1 CMD-SHELL true",
            "CMD-SHELL",
            "CMD",
        ] {
            assert!(
                parse_healthcheck(input).is_err(),
                "malformed healthcheck should fail: {input}"
            );
        }
        assert!(parse_healthcheck("NONE").unwrap().is_none());
    }

    #[test]
    fn expose_normalizes_supported_protocols_and_rejects_invalid_ports() {
        assert_eq!(
            parse_exposed_ports("80 443/TCP 5353/udp 989/sctp").unwrap(),
            ["80/tcp", "443/tcp", "5353/udp", "989/sctp"]
        );
        for input in ["0", "65536", "abc", "80/http", ""] {
            assert!(
                parse_exposed_ports(input).is_err(),
                "invalid EXPOSE: {input}"
            );
        }
    }

    #[test]
    fn stopsignal_normalizes_names_and_rejects_invalid_values() {
        assert_eq!(parse_stop_signal("SIGTERM").unwrap(), "SIGTERM");
        assert_eq!(parse_stop_signal("term").unwrap(), "SIGTERM");
        assert_eq!(parse_stop_signal("9").unwrap(), "9");
        for input in ["0", "65", "SIGNOPE", "SIGTERM extra", ""] {
            assert!(
                parse_stop_signal(input).is_err(),
                "invalid STOPSIGNAL: {input}"
            );
        }
    }

    #[test]
    fn maintainer_is_preserved_as_author_metadata_and_rejects_empty_values() {
        let stages = parse_stages("FROM scratch\nMAINTAINER Ferro Team <team@example.test>\n")
            .expect("MAINTAINER should parse");
        assert_eq!(
            stages[0].author.as_deref(),
            Some("Ferro Team <team@example.test>")
        );
        assert!(parse_maintainer("").is_err());
        assert!(parse_maintainer("bad\0author").is_err());
    }

    #[test]
    fn onbuild_triggers_are_preserved_and_forbidden_nested_instructions_fail() {
        let stages = parse_stages("FROM scratch\nONBUILD COPY . /src\nONBUILD RUN make\n")
            .expect("ONBUILD triggers should parse");
        assert_eq!(stages[0].onbuild, ["COPY . /src", "RUN make"]);
        for trigger in ["", "FROM alpine", "MAINTAINER legacy", "ONBUILD RUN true"] {
            assert!(
                parse_onbuild(trigger).is_err(),
                "invalid ONBUILD: {trigger}"
            );
        }
    }

    #[test]
    fn onbuild_application_merges_triggered_instructions_into_derived_stage() {
        let mut stage = parse_stages("FROM base\nRUN echo child\n")
            .expect("derived stage should parse")
            .remove(0);
        apply_onbuild_triggers(
            &mut stage,
            &["ENV FROM_BASE=1".to_string(), "RUN make".to_string()],
        )
        .expect("triggers should apply");
        assert!(stage.env.iter().any(|entry| entry == "FROM_BASE=1"));
        assert_eq!(stage.run.len(), 2);
    }

    #[test]
    fn cache_artifact_digest_check_rejects_replaced_files() {
        let temp = tempfile::tempdir().expect("cache artifact directory");
        let path = temp.path().join("layer");
        std::fs::write(&path, b"trusted").expect("write artifact");
        let digest = super::sha256_digest_bytes(b"trusted");
        assert!(file_matches_digest(&path, &digest));
        std::fs::write(&path, b"replaced").expect("replace artifact");
        assert!(!file_matches_digest(&path, &digest));
        assert!(!file_matches_digest(&temp.path().join("missing"), &digest));
    }

    #[test]
    fn named_contexts_are_bound_to_the_plan_and_reject_unsafe_sources() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("runtime");
        let context = temp.path().join("context");
        let assets = temp.path().join("assets");
        std::fs::create_dir_all(&context).unwrap();
        std::fs::create_dir_all(&assets).unwrap();
        let dockerfile = context.join("Dockerfile");
        std::fs::write(&dockerfile, "FROM scratch\nCOPY --from=assets app /app\n").unwrap();
        std::fs::write(assets.join("app"), "one").unwrap();
        let store = LocalImageStore::open(runtime.join("images")).unwrap();
        let mut contexts = HashMap::new();
        contexts.insert("assets".to_string(), assets.clone());
        let plan = prepare_dockerfile_build_with_contexts(
            &dockerfile,
            Some("local/app:test"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &contexts,
        )
        .unwrap();
        std::fs::write(assets.join("app"), "two").unwrap();
        let changed = prepare_dockerfile_build_with_contexts(
            &dockerfile,
            Some("local/app:test"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &contexts,
        )
        .unwrap();
        assert_ne!(plan.plan_digest(), changed.plan_digest());

        contexts.insert("bad/name".to_string(), assets.clone());
        assert!(prepare_dockerfile_build_with_contexts(
            &dockerfile,
            Some("local/app:test"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &contexts,
        )
        .is_err());
    }

    #[test]
    fn image_reference_is_valid_named_context_identity() {
        let temp = tempfile::tempdir().unwrap();
        let contexts = HashMap::from([(
            "tonistiigi/hellofs:latest".to_string(),
            temp.path().to_path_buf(),
        )]);
        let canonical = super::canonicalize_named_contexts(&contexts).unwrap();
        assert!(canonical.contains_key("tonistiigi/hellofs:latest"));
    }
    use crate::image_fetch::resolve_layer_paths_with_store;
    use crate::image_store::LocalImageStore;
    use crate::layer_compression::CompressionFormat;
    use std::fs;

    fn stage_root(runtime: &Path, index: usize) -> std::path::PathBuf {
        let prefix = format!("stage-{index}-");
        let mut roots = fs::read_dir(runtime.join("build"))
            .expect("build scratch directory")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_dir()
                    && path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
            })
            .collect::<Vec<_>>();
        roots.sort();
        assert_eq!(roots.len(), 1, "one scratch root for stage {index}");
        roots.pop().expect("stage scratch root")
    }

    #[test]
    fn builds_minimal_dockerfile() {
        let _env = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\nCOPY --link . /\n").expect("write");
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
    fn source_date_epoch_clamps_layer_entries_and_image_created_time() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\nCOPY payload /payload\n").expect("dockerfile");
        let payload = temp.path().join("payload");
        let file = fs::File::create(&payload).expect("payload");
        file.set_len(1).expect("payload size");
        file.set_times(
            std::fs::FileTimes::new()
                .set_modified(
                    std::time::UNIX_EPOCH
                        + std::time::Duration::from_secs(1_700_001_000),
                ),
        )
        .expect("payload mtime");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("store");
        let options = super::DockerfileExecutionOptions {
            source_date_epoch: Some(1_700_000_000),
            ..Default::default()
        };
        let plan = super::prepare_dockerfile_build_with_contexts_and_build_args_and_options(
            &dockerfile,
            Some("local/source-date-epoch:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &HashMap::new(),
            &HashMap::new(),
            &options,
        )
        .expect("plan");
        let permit = crate::authorization::surface::SurfaceAuthorization::compatibility()
            .authorize_image_build_plan(
                &crate::authorization::RequestOrigin::cli_current().expect("origin"),
                &plan,
            )
            .expect("permit");
        let result = super::execute_dockerfile_build_authorized(plan, &store, permit)
            .expect("build");
        let config: serde_json::Value = serde_json::from_slice(
            &fs::read(
                runtime
                    .join("images/configs")
                    .join(result.config_digest.replace(':', "_")),
            )
            .expect("config"),
        )
        .expect("config JSON");
        assert_eq!(config["created"], "2023-11-14T22:13:20Z");
        let layers = resolve_layer_paths_with_store(&runtime, &result.reference, &store)
            .expect("layers");
        let decoder = flate2::read::GzDecoder::new(fs::File::open(&layers[0]).expect("layer"));
        let mut archive = tar::Archive::new(decoder);
        let mtime = archive
            .entries()
            .expect("entries")
            .find_map(|entry| {
                let entry = entry.expect("entry");
                (entry.path().expect("path").as_ref() == std::path::Path::new("payload"))
                    .then(|| entry.header().mtime().expect("mtime"))
            })
            .expect("payload entry");
        assert_eq!(mtime, 1_700_000_000);
    }

    #[test]
    fn build_args_bake_multiple_values_into_the_image_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch\nARG FIRST=default-first\nARG SECOND=default-second\nENV FIRST=${FIRST} SECOND=${SECOND}\nLABEL org.ferrocrate.first=${FIRST} org.ferrocrate.second=${SECOND}\n",
        )
        .expect("write Dockerfile");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("open store");
        let build_args = HashMap::from([
            ("FIRST".to_string(), "one".to_string()),
            ("SECOND".to_string(), "two".to_string()),
        ]);

        let plan = prepare_dockerfile_build_with_contexts_and_build_args(
            &dockerfile,
            Some("local/build-args:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &HashMap::new(),
            &build_args,
        )
        .expect("prepare build plan");
        let permit = crate::authorization::surface::SurfaceAuthorization::compatibility()
            .authorize_image_build_plan(
                &crate::authorization::RequestOrigin::cli_current().expect("origin"),
                &plan,
            )
            .expect("authorize build plan");
        let result = super::execute_dockerfile_build_authorized(plan, &store, permit)
            .expect("build image");
        let config = fs::read_to_string(
            runtime
                .join("images")
                .join("configs")
                .join(result.config_digest.replace(':', "_")),
        )
        .expect("read image config");
        let config: serde_json::Value = serde_json::from_str(&config).expect("parse image config");
        assert_eq!(config["config"]["Env"], serde_json::json!(["FIRST=one", "SECOND=two"]));
        assert_eq!(config["config"]["Labels"]["org.ferrocrate.first"], "one");
        assert_eq!(config["config"]["Labels"]["org.ferrocrate.second"], "two");
    }

    #[test]
    fn buildkit_target_os_version_expands_and_is_written_to_image_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch\nARG TARGETOSVERSION\nCOPY <<EOF /osversion\n${TARGETOSVERSION}\nEOF\n",
        )
        .expect("write Dockerfile");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("open store");
        let build_args = super::automatic_platform_args_for_target(Some(
            "windows(10.0.20348.1006)/amd64",
        ))
        .expect("target platform");

        let options = super::DockerfileExecutionOptions {
            target_platform: Some("windows(10.0.20348.1006)/amd64".to_string()),
            ..Default::default()
        };
        let plan = super::prepare_dockerfile_build_with_contexts_and_build_args_and_options(
            &dockerfile,
            Some("local/os-version:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &HashMap::new(),
            &build_args,
            &options,
        )
        .expect("prepare build plan");
        let permit = crate::authorization::surface::SurfaceAuthorization::compatibility()
            .authorize_image_build_plan(
                &crate::authorization::RequestOrigin::cli_current().expect("origin"),
                &plan,
            )
            .expect("authorize build plan");
        let result = super::execute_dockerfile_build_authorized(plan, &store, permit)
            .expect("build image");
        assert_eq!(
            fs::read_to_string(stage_root(&runtime, 0).join("osversion"))
                .expect("TARGETOSVERSION output"),
            "10.0.20348.1006"
        );
        let config = fs::read_to_string(
            runtime
                .join("images")
                .join("configs")
                .join(result.config_digest.replace(':', "_")),
        )
        .expect("read image config");
        let config: serde_json::Value = serde_json::from_str(&config).expect("parse image config");
        assert_eq!(config["os"], "windows");
        assert_eq!(config["architecture"], "amd64");
        assert_eq!(config["os.version"], "10.0.20348.1006");
    }

    #[test]
    fn copy_relative_destination_is_resolved_from_workdir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\nWORKDIR /app\nCOPY source d\n").expect("dockerfile");
        fs::create_dir_all(temp.path().join("source")).expect("source");
        fs::write(temp.path().join("source/value"), "value").expect("value");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("store");
        build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/workdir-copy:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect("build");
        assert_eq!(
            fs::read_to_string(stage_root(&runtime, 0).join("app/d/value"))
                .expect("WORKDIR COPY result"),
            "value"
        );
    }

    #[test]
    fn copy_preserves_symlinks_and_empty_directories_in_the_layer() {
        // S5: a directory containing a symlink must arrive whole, links
        // preserved as links instead of silently dropped with their parent.
        #[cfg(unix)]
        {
            let _env = crate::test_support::acquire_env_lock();
            let temp = tempfile::tempdir().expect("tempdir");
            let dockerfile = temp.path().join("Dockerfile");
            fs::write(&dockerfile, "FROM scratch\nCOPY d /d\n").expect("dockerfile");
            let source = temp.path().join("d");
            fs::create_dir_all(source.join("bin")).expect("bin dir");
            fs::write(source.join("real.txt"), "content").expect("real.txt");
            std::os::unix::fs::symlink("../real.txt", source.join("bin/link"))
                .expect("relative link");
            std::os::unix::fs::symlink("/d/real.txt", source.join("absolute"))
                .expect("absolute link");
            std::os::unix::fs::symlink("missing-target", source.join("bin/dangling"))
                .expect("dangling link");
            fs::create_dir_all(source.join("empty")).expect("empty dir");

            let runtime = temp.path().join("runtime");
            let store = LocalImageStore::open(runtime.join("images")).expect("store");
            build_from_dockerfile_with_store_and_compression(
                &dockerfile,
                Some("local/symlink-copy:latest"),
                &runtime,
                CompressionFormat::Gzip,
                &store,
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
            )
            .expect("build");

            let stage = stage_root(&runtime, 0).join("d");
            assert_eq!(
                fs::read_to_string(stage.join("real.txt")).expect("regular file"),
                "content"
            );
            assert!(
                stage.join("bin").is_dir(),
                "directory holding a link survives"
            );
            assert_eq!(
                fs::read_link(stage.join("bin/link")).expect("relative link"),
                Path::new("../real.txt")
            );
            assert_eq!(
                fs::read_link(stage.join("bin/dangling")).expect("dangling link"),
                Path::new("missing-target")
            );
            assert_eq!(
                fs::read_link(stage.join("absolute")).expect("absolute link"),
                Path::new("/d/real.txt")
            );
            assert!(stage.join("empty").is_dir(), "empty directory survives");
        }
    }

    #[test]
    fn context_hash_includes_symlink_targets() {
        #[cfg(unix)]
        {
            let temp = tempfile::tempdir().expect("tempdir");
            let dockerfile = temp.path().join("Dockerfile");
            fs::write(&dockerfile, "FROM scratch\n").expect("dockerfile");
            fs::write(temp.path().join("payload"), "one").expect("payload");
            std::os::unix::fs::symlink("payload", temp.path().join("latest")).expect("link");

            let first = hash_context_dir(temp.path(), &dockerfile).expect("hash");
            fs::remove_file(temp.path().join("latest")).expect("remove link");
            std::os::unix::fs::symlink("unrelated", temp.path().join("latest")).expect("retarget");
            let second = hash_context_dir(temp.path(), &dockerfile).expect("hash");

            assert_ne!(first, second);
        }
    }

    #[test]
    fn copy_multiple_sources_to_workdir_dot_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch\nWORKDIR /app\nCOPY package.json package-lock.json ./\n",
        )
        .expect("dockerfile");
        fs::write(temp.path().join("package.json"), "{}").expect("package");
        fs::write(temp.path().join("package-lock.json"), "{}").expect("lock");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("store");
        build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/workdir-dot:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect("build");
        let stage = stage_root(&runtime, 0);
        assert!(stage.join("app/package.json").is_file());
        assert!(stage.join("app/package-lock.json").is_file());
    }

    #[test]
    fn copy_directory_to_workdir_dot_keeps_directory_contents_at_destination() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch\nWORKDIR /app/src/frontend\nCOPY src/frontend/package.json src/frontend/package-lock.json ./\nCOPY src/frontend ./\n",
        )
        .expect("dockerfile");
        let frontend = temp.path().join("src/frontend");
        fs::create_dir_all(&frontend).expect("frontend");
        fs::write(frontend.join("package.json"), "{}").expect("package");
        fs::write(frontend.join("package-lock.json"), "{}").expect("lock");
        fs::write(frontend.join("tsconfig.json"), "{}").expect("tsconfig");

        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("store");
        build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/workdir-directory-dot:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect("build");

        let frontend = stage_root(&runtime, 0).join("app/src/frontend");
        assert!(frontend.join("package.json").is_file());
        assert!(frontend.join("package-lock.json").is_file());
        assert!(frontend.join("tsconfig.json").is_file());
        assert!(
            !frontend.join("frontend").exists(),
            "directory source must contribute its contents, as Docker does"
        );
    }

    #[test]
    fn copy_expands_context_globs_without_copying_non_matches() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\nCOPY package*.json /app/\n").unwrap();
        fs::write(temp.path().join("package.json"), "manifest").unwrap();
        fs::write(temp.path().join("package-lock.json"), "lock").unwrap();
        fs::write(temp.path().join("package.txt"), "not json").unwrap();
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).unwrap();

        build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/copy-glob:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect("glob COPY build");

        let app = stage_root(&runtime, 0).join("app");
        assert_eq!(
            fs::read_to_string(app.join("package.json")).unwrap(),
            "manifest"
        );
        assert_eq!(
            fs::read_to_string(app.join("package-lock.json")).unwrap(),
            "lock"
        );
        assert!(!app.join("package.txt").exists());
    }

    #[test]
    fn from_named_stage_uses_the_preceding_stage_filesystem() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch AS base\nCOPY artifact /tool\nFROM base\nCOPY marker /marker\n",
        )
        .expect("dockerfile");
        fs::write(temp.path().join("artifact"), "compiled").expect("artifact");
        fs::write(temp.path().join("marker"), "final").expect("marker");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("store");

        build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/named-stage:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect("named stage build");

        assert_eq!(
            fs::read_to_string(stage_root(&runtime, 1).join("tool")).unwrap(),
            "compiled"
        );
        assert_eq!(
            fs::read_to_string(stage_root(&runtime, 1).join("marker")).unwrap(),
            "final"
        );
    }

    #[test]
    fn copy_from_named_stage_uses_its_uniquely_allocated_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch AS seed\nWORKDIR /out\nFROM seed AS source\nCOPY artifact artifact\nFROM scratch\nCOPY --from=source /out/artifact /artifact\n",
        )
        .expect("dockerfile");
        fs::write(temp.path().join("artifact"), "compiled").expect("artifact");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("store");

        build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/copy-named-stage:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect("COPY --from named stage build");

        assert_eq!(
            fs::read_to_string(stage_root(&runtime, 2).join("artifact")).unwrap(),
            "compiled"
        );
    }

    #[test]
    fn copy_from_multiple_sources_preserves_each_source() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch AS source\nCOPY one /one\nCOPY two /two\nFROM scratch\nCOPY --from=source /one /two /out/\n",
        )
        .expect("dockerfile");
        fs::write(temp.path().join("one"), "one").expect("one");
        fs::write(temp.path().join("two"), "two").expect("two");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("store");

        build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/copy-many:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect("COPY --from multiple sources build");

        assert_eq!(fs::read_to_string(stage_root(&runtime, 1).join("out/one")).unwrap(), "one");
        assert_eq!(fs::read_to_string(stage_root(&runtime, 1).join("out/two")).unwrap(), "two");
    }

    #[test]
    fn stage_environment_keeps_base_path_and_allows_dockerfile_overrides() {
        let base = BaseImageInfo {
            layers: Vec::new(),
            descriptors: Vec::new(),
            digest: None,
            onbuild: Vec::new(),
            env: vec![
                "PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                "RUSTUP_HOME=/usr/local/rustup".to_string(),
            ],
            config: super::BaseConfig::default(),
        };

        assert_eq!(
            super::stage_environment(
                &base,
                &["PATH=/custom/bin".to_string(), "PORT=8080".to_string()]
            ),
            vec![
                "PATH=/custom/bin".to_string(),
                "RUSTUP_HOME=/usr/local/rustup".to_string(),
                "PORT=8080".to_string(),
            ]
        );
    }

    #[test]
    fn copy_dot_into_workdir_copies_context_contents_not_context_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\nWORKDIR /src\nCOPY . .\n").unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\n",
        )
        .unwrap();
        fs::write(temp.path().join("generated-checkstyle.java"), "ignored").unwrap();
        fs::write(
            temp.path().join(".dockerignore"),
            "generated-checkstyle.java\n",
        )
        .unwrap();
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).unwrap();

        build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/copy-dot:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect("COPY . . build");

        let stage = stage_root(&runtime, 0);
        assert!(stage.join("src/Cargo.toml").is_file());
        assert!(!stage.join("src/src/Cargo.toml").exists());
        assert!(!stage.join("src/generated-checkstyle.java").exists());
    }

    #[test]
    fn repeated_build_ignores_runtime_scratch_nested_in_context() {
        let _env = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\nCOPY . /\n").expect("write");
        fs::write(temp.path().join("hello.txt"), "stable").expect("write file");

        let runtime_dir = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime_dir.join("images")).expect("open store");
        let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();
        let first = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/repeat:latest"),
            &runtime_dir,
            CompressionFormat::Gzip,
            &store,
            &authority,
        )
        .expect("first build");
        let second = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/repeat:latest"),
            &runtime_dir,
            CompressionFormat::Gzip,
            &store,
            &authority,
        )
        .expect("second build");
        assert_eq!(first.layer_digest, second.layer_digest);
    }

    #[test]
    fn prepared_plan_ignores_nested_runtime_scratch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\nCOPY . /\n").expect("write");
        fs::write(temp.path().join("hello.txt"), "stable").expect("write file");
        let runtime_dir = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime_dir.join("images")).expect("open store");

        let first = prepare_dockerfile_build(
            &dockerfile,
            Some("local/prepared:latest"),
            &runtime_dir,
            CompressionFormat::Gzip,
            &store,
        )
        .expect("first plan");
        fs::create_dir_all(runtime_dir.join("build/context-previous/src")).expect("scratch");
        fs::write(
            runtime_dir.join("build/context-previous/src/generated.txt"),
            "must not bind",
        )
        .expect("scratch file");
        let second = prepare_dockerfile_build(
            &dockerfile,
            Some("local/prepared:latest"),
            &runtime_dir,
            CompressionFormat::Gzip,
            &store,
        )
        .expect("second plan");
        assert_eq!(first.plan_digest(), second.plan_digest());
    }

    #[test]
    fn stores_build_cache_entry() {
        let _env = crate::test_support::acquire_env_lock();
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
        assert_eq!(entry.stage_layer_digests.len(), 1);
        assert!(entry.stage_layer_digests[0].starts_with("sha256:"));
        assert!(!runtime_dir.join("images/build-cache.json.tmp").exists());
    }

    #[test]
    fn build_cache_key_binds_fields_and_scratch_identity() {
        let scratch = BaseImageInfo {
            layers: Vec::new(),
            descriptors: Vec::new(),
            digest: None,
            onbuild: Vec::new(),
            env: Vec::new(),
            config: super::BaseConfig::default(),
        };
        let keyed = BaseImageInfo {
            digest: Some("sha256:base".to_string()),
            ..scratch.clone()
        };
        let scratch_key = build_cache_key(
            "FROM scratch\n",
            CompressionFormat::Gzip,
            "context",
            &[scratch],
            BUILD_CACHE_PLATFORM,
        );
        let keyed_key = build_cache_key(
            "FROM scratch\n",
            CompressionFormat::Gzip,
            "context",
            &[keyed],
            BUILD_CACHE_PLATFORM,
        );
        assert_ne!(scratch_key, keyed_key);
        assert_ne!(
            scratch_key,
            build_cache_key(
                "FROM scratch\nRUN true\n",
                CompressionFormat::Gzip,
                "context",
                &[],
                BUILD_CACHE_PLATFORM
            )
        );
        // The key is a pure function of its inputs: identical arguments
        // derive an identical key, and a different platform derives a
        // different key so cross-platform caches miss instead of reusing.
        assert_eq!(
            scratch_key,
            build_cache_key(
                "FROM scratch\n",
                CompressionFormat::Gzip,
                "context",
                &[BaseImageInfo {
                    layers: Vec::new(),
                    descriptors: Vec::new(),
                    digest: None,
                    onbuild: Vec::new(),
                    env: Vec::new(),
                    config: super::BaseConfig::default(),
                }],
                BUILD_CACHE_PLATFORM
            )
        );
        assert_ne!(
            scratch_key,
            build_cache_key(
                "FROM scratch\n",
                CompressionFormat::Gzip,
                "context",
                &[],
                "linux/arm64"
            )
        );
    }

    #[test]
    fn interrupted_build_resumes_from_digest_bound_stage_checkpoint() {
        let _env = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().unwrap();
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\nCOPY . /\n").unwrap();
        fs::write(temp.path().join("hello.txt"), "resume me").unwrap();
        let runtime_holder = tempfile::tempdir().unwrap();
        let runtime = runtime_holder.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).unwrap();
        let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();
        let first = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/resume:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &authority,
        )
        .unwrap();
        assert!(stage_checkpoint_path(&runtime).is_file());
        let checkpoint = load_stage_checkpoints(&runtime).unwrap();
        assert_eq!(checkpoint.len(), 1);
        assert_eq!(checkpoint.get(&0).unwrap().layer_digest, first.layer_digest);
        fs::remove_file(build_cache_path(&runtime)).unwrap();
        fs::remove_dir_all(stage_root(&runtime, 0)).unwrap();
        let second = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/resume:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &authority,
        )
        .unwrap();
        assert_eq!(first.layer_digest, second.layer_digest);
        assert!(stage_root(&runtime, 0).is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn checkpoint_restore_preserves_artifacts_copied_from_a_build_stage() {
        let _env = crate::test_support::acquire_env_lock();
        if skip_unavailable_rootless_build_sandbox() {
            return;
        }
        let Some(busybox) = static_busybox() else {
            eprintln!("skipping: no static /usr/bin/busybox on this host");
            return;
        };
        let temp = tempfile::tempdir().expect("tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch AS addon-build\n\
             COPY busybox /busybox\n\
             COPY native-addon /opt/addon.node\n\
             RUN [\"/busybox\", \"true\"]\n\
             FROM scratch AS test\n\
             COPY busybox /busybox\n\
             RUN [\"/busybox\", \"sh\", \"-c\", \"rm -f /opt/addon.node\"]\n\
             COPY --from=addon-build /opt/addon.node /opt/addon.node\n\
             RUN [\"/busybox\", \"sh\", \"-c\", \"test -s /opt/addon.node\"]\n",
        )
        .expect("dockerfile");
        fs::copy(busybox, temp.path().join("busybox")).expect("copy busybox");
        fs::write(temp.path().join("native-addon"), b"native-addon").expect("native addon");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("image store");
        let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();

        build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/checkpoint-addon:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &authority,
        )
        .expect("seed build");
        fs::remove_file(build_cache_path(&runtime)).expect("remove build cache");
        fs::remove_dir_all(stage_root(&runtime, 0)).expect("remove build stage root");
        fs::remove_dir_all(stage_root(&runtime, 1)).expect("remove test stage root");

        build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/checkpoint-addon:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &authority,
        )
        .expect("checkpointed build");
        assert!(
            stage_root(&runtime, 1).join("opt/addon.node").is_file(),
            "a checkpointed stage must retain files copied from its build stage"
        );
    }

    #[test]
    fn cache_entry_records_source_provenance_when_context_changes() {
        let _env = crate::test_support::acquire_env_lock();
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
                    stage_layer_digests: Vec::new(),
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
        // Pruning removes metadata records only. Content-addressed blobs
        // stay, so a later rebuild of a pruned key still finds its layers.
        let retained_blob = layer_blob_path(&runtime, "sha256:new");
        fs::create_dir_all(retained_blob.parent().unwrap()).unwrap();
        fs::write(&retained_blob, b"blob").unwrap();
        assert_eq!(prune_build_cache(&runtime, 1).unwrap(), 2);
        let retained = load_build_cache(&runtime).unwrap();
        assert!(retained.contains_key("new"));
        assert_eq!(retained.len(), 1);
        assert!(retained_blob.exists());
    }

    #[test]
    fn prunes_equal_timestamp_entries_by_cache_key() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().to_path_buf();
        let mut cache = HashMap::new();
        for key in ["zeta", "alpha"] {
            cache.insert(
                key.to_string(),
                BuildCacheEntry {
                    cache_key: key.to_string(),
                    created_at_unix: 10,
                    context_digest: String::new(),
                    dockerfile_digest: String::new(),
                    base_digests: Vec::new(),
                    stage_layer_digests: Vec::new(),
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
        assert_eq!(prune_build_cache(&runtime, 1).unwrap(), 1);
        let retained = load_build_cache(&runtime).unwrap();
        assert!(retained.contains_key("zeta"));
        assert!(!retained.contains_key("alpha"));
    }

    /// Build a manifest JSON whose config and final layer bind the recorded
    /// entry digests, matching what a real build records.
    fn bound_manifest_json(config_digest: &str, layer_digest: &str) -> String {
        serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": 2
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": layer_digest,
                "size": 1
            }]
        })
        .to_string()
    }

    #[test]
    fn exports_and_imports_build_cache_metadata_atomically() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let mut cache = HashMap::new();
        let cache_key = "a".repeat(64);
        let config_json = "{}";
        let config_digest = sha256_digest_bytes(config_json.as_bytes());
        let layer_digest = format!("sha256:{}", "1".repeat(64));
        cache.insert(
            cache_key.clone(),
            BuildCacheEntry {
                cache_key: cache_key.clone(),
                created_at_unix: 1,
                context_digest: String::new(),
                dockerfile_digest: String::new(),
                base_digests: Vec::new(),
                stage_layer_digests: vec![format!("sha256:{}", "3".repeat(64))],
                layer_digest: layer_digest.clone(),
                layer_size: 1,
                layer_media_type: "application/octet-stream".to_string(),
                config_digest: config_digest.clone(),
                config_json: config_json.to_string(),
                manifest_json: bound_manifest_json(&config_digest, &layer_digest),
            },
        );
        save_build_cache(source.path(), &cache).unwrap();
        let export = source.path().join("export.json");
        export_build_cache(source.path(), &export).unwrap();
        assert_eq!(import_build_cache(target.path(), &export).unwrap(), 1);
        assert_eq!(load_build_cache(target.path()).unwrap().len(), 1);

        cache.values_mut().next().unwrap().context_digest = "conflict".to_string();
        save_build_cache(source.path(), &cache).unwrap();
        let conflicting_export = source.path().join("conflicting-export.json");
        export_build_cache(source.path(), &conflicting_export).unwrap();
        let error = import_build_cache(target.path(), &conflicting_export)
            .expect_err("conflicting cache metadata must fail closed");
        assert!(error.to_string().contains("conflicts with local key"));
    }

    #[test]
    fn exports_and_imports_cache_artifacts_for_portable_hits() {
        let _env = crate::test_support::acquire_env_lock();
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let context = source.path().join("context");
        fs::create_dir_all(&context).unwrap();
        fs::write(context.join("Dockerfile"), "FROM scratch\nCOPY . /\n").unwrap();
        fs::write(context.join("payload"), "portable cache").unwrap();
        let source_runtime = source.path().join("runtime");
        let source_store = LocalImageStore::open(source_runtime.join("images")).unwrap();
        let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();
        let first = build_from_dockerfile_with_store_and_compression(
            &context.join("Dockerfile"),
            Some("local/portable:latest"),
            &source_runtime,
            CompressionFormat::Gzip,
            &source_store,
            &authority,
        )
        .unwrap();
        let export = source.path().join("cache.json");
        export_build_cache(&source_runtime, &export).unwrap();

        let target_runtime = target.path().join("runtime");
        let target_store = LocalImageStore::open(target_runtime.join("images")).unwrap();
        assert_eq!(import_build_cache(&target_runtime, &export).unwrap(), 1);
        let second = build_from_dockerfile_with_store_and_compression(
            &context.join("Dockerfile"),
            Some("local/portable:latest"),
            &target_runtime,
            CompressionFormat::Gzip,
            &target_store,
            &authority,
        )
        .unwrap();
        assert_eq!(first.layer_digest, second.layer_digest);
        assert_eq!(first.config_digest, second.config_digest);
        // The hit must come from the imported cache, not a deterministic
        // rebuild: the fast path never creates stage build directories and
        // reads the imported layer blob directly.
        assert!(
            !target_runtime.join("build").exists(),
            "imported cache hit must not rebuild stages"
        );
        assert!(layer_blob_path(&target_runtime, &second.layer_digest).exists());
    }

    #[test]
    fn import_build_cache_rejects_unbound_or_malformed_artifacts() {
        let runtime = tempfile::tempdir().unwrap();
        let source = runtime.path().join("invalid-cache.json");
        let key = "b".repeat(64);
        let payload = serde_json::json!({
            key.clone(): {
                "cache_key": "c".repeat(64),
                "created_at_unix": 1,
                "context_digest": "context",
                "dockerfile_digest": "dockerfile",
                "base_digests": [],
                "layer_digest": "sha256:bad",
                "layer_size": 1,
                "layer_media_type": "application/octet-stream",
                "config_digest": "sha256:bad",
                "config_json": "{}",
                "manifest_json": "{}"
            }
        });
        fs::write(&source, serde_json::to_vec(&payload).unwrap()).unwrap();
        let error = import_build_cache(runtime.path(), &source).expect_err("invalid cache");
        assert!(error.to_string().contains("provenance validation"));
        assert!(!build_cache_path(runtime.path()).exists());
    }

    #[test]
    fn import_build_cache_rejects_malformed_stage_provenance() {
        let runtime = tempfile::tempdir().unwrap();
        let source = runtime.path().join("invalid-stage-cache.json");
        let key = "a".repeat(64);
        let digest = format!("sha256:{}", "0".repeat(64));
        let payload = serde_json::json!({
            key.clone(): {
                "cache_key": key,
                "created_at_unix": 1,
                "context_digest": "context",
                "dockerfile_digest": "dockerfile",
                "base_digests": ["scratch"],
                "stage_layer_digests": ["not-a-digest"],
                "layer_digest": digest,
                "layer_size": 1,
                "layer_media_type": "application/octet-stream",
                "config_digest": format!("sha256:{}", "1".repeat(64)),
                "config_json": "{}",
                "manifest_json": "{}"
            }
        });
        fs::write(&source, serde_json::to_vec(&payload).unwrap()).unwrap();
        let error = import_build_cache(runtime.path(), &source)
            .expect_err("malformed stage provenance must fail closed");
        assert!(error.to_string().contains("provenance validation"));
        assert!(!build_cache_path(runtime.path()).exists());
    }

    #[cfg(unix)]
    #[test]
    fn import_build_cache_rejects_symlink_sources() {
        let runtime = tempfile::tempdir().unwrap();
        let target = runtime.path().join("target.json");
        let source = runtime.path().join("source.json");
        fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, &source).unwrap();
        let error = import_build_cache(runtime.path(), &source).expect_err("symlink source");
        assert!(error.to_string().contains("regular file"));
    }

    #[test]
    fn import_build_cache_rejects_oversized_sources() {
        let runtime = tempfile::tempdir().unwrap();
        let source = runtime.path().join("oversized.json");
        fs::write(&source, vec![b' '; 16 * 1024 * 1024 + 1]).unwrap();
        let error = import_build_cache(runtime.path(), &source).expect_err("oversized source");
        assert!(error.to_string().contains("16 MiB"));
    }

    /// A fully valid entry fixture that passes provenance validation.
    fn provenance_bound_entry() -> BuildCacheEntry {
        let config_json = r#"{"architecture":"amd64","os":"linux"}"#;
        let config_digest = sha256_digest_bytes(config_json.as_bytes());
        let layer_digest = format!("sha256:{}", "7".repeat(64));
        BuildCacheEntry {
            cache_key: "d".repeat(64),
            created_at_unix: 5,
            context_digest: "context".to_string(),
            dockerfile_digest: "dockerfile".to_string(),
            base_digests: vec!["scratch".to_string()],
            stage_layer_digests: vec![layer_digest.clone()],
            layer_digest: layer_digest.clone(),
            layer_size: 3,
            layer_media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
            config_digest: config_digest.clone(),
            config_json: config_json.to_string(),
            manifest_json: bound_manifest_json(&config_digest, &layer_digest),
        }
    }

    fn write_import_source(
        runtime: &std::path::Path,
        entry: &BuildCacheEntry,
    ) -> std::path::PathBuf {
        let source = runtime.join("cache-import.json");
        let payload =
            serde_json::json!({ entry.cache_key.clone(): serde_json::to_value(entry).unwrap() });
        fs::write(&source, serde_json::to_vec(&payload).unwrap()).unwrap();
        source
    }

    #[test]
    fn import_build_cache_accepts_provenance_bound_entry() {
        let runtime = tempfile::tempdir().unwrap();
        let source = write_import_source(runtime.path(), &provenance_bound_entry());
        assert_eq!(import_build_cache(runtime.path(), &source).unwrap(), 1);
    }

    #[test]
    fn import_build_cache_rejects_config_bytes_digest_mismatch() {
        let runtime = tempfile::tempdir().unwrap();
        let mut entry = provenance_bound_entry();
        // Same claimed config digest, different embedded bytes.
        entry.config_json = entry.config_json.replace("amd64", "arm64");
        let source = write_import_source(runtime.path(), &entry);
        let error = import_build_cache(runtime.path(), &source)
            .expect_err("config bytes must bind the recorded digest");
        assert!(error.to_string().contains("config digest"));
        assert!(!build_cache_path(runtime.path()).exists());
    }

    #[test]
    fn import_build_cache_rejects_manifest_layer_binding_mismatch() {
        let runtime = tempfile::tempdir().unwrap();
        let mut entry = provenance_bound_entry();
        // The manifest's final layer disagrees with the recorded layer.
        let wrong_layer = format!("sha256:{}", "e".repeat(64));
        entry.manifest_json = bound_manifest_json(&entry.config_digest, &wrong_layer);
        let source = write_import_source(runtime.path(), &entry);
        let error = import_build_cache(runtime.path(), &source)
            .expect_err("manifest must bind the recorded layer digest");
        assert!(error.to_string().contains("does not bind"));
        assert!(!build_cache_path(runtime.path()).exists());
    }

    /// A single-threaded local OCI registry served over plain HTTP on
    /// 127.0.0.1. It stores pushed blobs and manifests in memory so a
    /// cache export can be imported back without external network access.
    struct LocalTestRegistry {
        addr: String,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl LocalTestRegistry {
        fn run() -> Self {
            use std::sync::atomic::{AtomicBool, Ordering};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let flag = stop.clone();
            listener.set_nonblocking(true).unwrap();
            std::thread::spawn(move || {
                let blobs =
                    std::sync::Arc::new(std::sync::Mutex::new(HashMap::<String, Vec<u8>>::new()));
                let manifests =
                    std::sync::Arc::new(std::sync::Mutex::new(HashMap::<String, Vec<u8>>::new()));
                while !flag.load(Ordering::Relaxed) {
                    let (stream, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(_) => {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            continue;
                        }
                    };
                    let blobs = blobs.clone();
                    let manifests = manifests.clone();
                    std::thread::spawn(move || {
                        let _ = serve_registry_request(stream, &blobs, &manifests);
                    });
                }
            });
            Self { addr, stop }
        }

        fn reference(&self, repository: &str, tag: &str) -> String {
            format!("registry://{}/{repository}:{tag}", self.addr)
        }
    }

    impl Drop for LocalTestRegistry {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn serve_registry_request(
        mut stream: std::net::TcpStream,
        blobs: &std::sync::Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>>,
        manifests: &std::sync::Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>>,
    ) -> std::io::Result<()> {
        use std::io::{Read, Write};
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        // Read headers.
        let header_end = loop {
            if let Some(position) = find_double_crlf(&buffer) {
                break position;
            }
            match stream.read(&mut chunk) {
                Ok(0) => return Ok(()),
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                Err(_) => return Ok(()),
            }
        };
        let headers = String::from_utf8_lossy(&buffer[..header_end]).to_string();
        let mut lines = headers.lines();
        let request_line = lines.next().unwrap_or_default().to_string();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let raw_path = parts.next().unwrap_or_default().to_string();
        let content_length = lines
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        // Read body.
        let mut body = buffer[header_end + 4..].to_vec();
        while body.len() < content_length {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => body.extend_from_slice(&chunk[..read]),
                Err(_) => break,
            }
        }
        body.truncate(content_length);

        let (path, query) = raw_path.split_once('?').unwrap_or((raw_path.as_str(), ""));
        let response = if path == "/v2/" {
            http_response(200, b"")
        } else if let Some(rest) = path.strip_suffix("/blobs/uploads/") {
            let _ = rest;
            let location = format!("{path}transfer");
            format!(
                "HTTP/1.1 202 Accepted\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .into_bytes()
        } else if path.contains("/blobs/uploads/") {
            let digest = query
                .split('&')
                .find_map(|pair| pair.strip_prefix("digest="))
                .unwrap_or_default()
                .to_string();
            if digest.is_empty() {
                http_response(400, b"missing digest")
            } else {
                blobs.lock().unwrap().insert(digest, body);
                http_response(201, b"")
            }
        } else if let Some(digest) = path.strip_prefix("/v2/") {
            let digest = digest
                .split_once("/blobs/")
                .map(|(_, blob)| blob.to_string());
            if let Some(digest) = digest {
                match blobs.lock().unwrap().get(&digest) {
                    Some(payload) => http_response(200, payload),
                    None => http_response(404, b"blob not found"),
                }
            } else {
                let reference = path
                    .rsplit_once("/manifests/")
                    .map(|(_, reference)| reference.to_string());
                match (method.as_str(), reference) {
                    ("PUT", Some(reference)) => {
                        manifests.lock().unwrap().insert(reference, body);
                        http_response(201, b"")
                    }
                    ("GET", Some(reference)) => match manifests.lock().unwrap().get(&reference) {
                        Some(payload) => http_response(200, payload),
                        None => http_response(404, b"manifest not found"),
                    },
                    _ => http_response(405, b"unsupported"),
                }
            }
        } else {
            http_response(404, b"not found")
        };
        stream.write_all(&response)?;
        stream.flush()?;
        Ok(())
    }

    fn find_double_crlf(buffer: &[u8]) -> Option<usize> {
        buffer.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn http_response(status: u16, body: &[u8]) -> Vec<u8> {
        let reason = match status {
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            400 => "Bad Request",
            404 => "Not Found",
            _ => "Error",
        };
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut response = head.into_bytes();
        response.extend_from_slice(body);
        response
    }

    #[test]
    fn registry_cache_export_import_round_trip_proves_cache_hit() {
        let _env = crate::test_support::acquire_env_lock();
        let registry = LocalTestRegistry::run();
        let source = tempfile::tempdir().unwrap();
        let context = source.path().join("context");
        fs::create_dir_all(&context).unwrap();
        fs::write(context.join("Dockerfile"), "FROM scratch\nCOPY . /\n").unwrap();
        fs::write(context.join("payload"), "registry exchange").unwrap();
        let source_runtime = source.path().join("runtime");
        let source_store = LocalImageStore::open(source_runtime.join("images")).unwrap();
        let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();
        let first = build_from_dockerfile_with_store_and_compression(
            &context.join("Dockerfile"),
            Some("local/registry-cache:latest"),
            &source_runtime,
            CompressionFormat::Gzip,
            &source_store,
            &authority,
        )
        .unwrap();

        let reference = registry.reference("team/cache", "latest");
        let pushed = export_build_cache_to_registry(&source_runtime, &reference, None)
            .expect("export cache to registry");
        // Metadata plus at least the final layer and config blobs.
        assert!(pushed >= 3, "expected metadata, layer, and config pushes");

        let target = tempfile::tempdir().unwrap();
        let target_runtime = target.path().join("runtime");
        let imported = import_build_cache_from_registry(&target_runtime, &reference, None)
            .expect("import cache from registry");
        assert_eq!(imported, 1);

        let target_store = LocalImageStore::open(target_runtime.join("images")).unwrap();
        let second = build_from_dockerfile_with_store_and_compression(
            &context.join("Dockerfile"),
            Some("local/registry-cache:latest"),
            &target_runtime,
            CompressionFormat::Gzip,
            &target_store,
            &authority,
        )
        .unwrap();
        assert_eq!(first.layer_digest, second.layer_digest);
        assert_eq!(first.config_digest, second.config_digest);
        // The registry import itself uses build/ as its transfer directory;
        // a cache hit must not add any stage directories to it.
        assert!(
            fs::read_dir(target_runtime.join("build"))
                .map(|entries| entries
                    .filter_map(Result::ok)
                    .all(|entry| !entry.file_name().to_string_lossy().starts_with("stage-0-")))
                .unwrap_or(true),
            "imported registry cache hit must not rebuild stages"
        );
        assert!(layer_blob_path(&target_runtime, &second.layer_digest).exists());
    }

    #[test]
    fn interpolate_value_escapes_dollar_with_backslash() {
        use super::interpolate_value;
        // Docker semantics: `\$` is a literal `$`, so a runtime-provided
        // variable such as SSH_AUTH_SOCK can reach the RUN shell unexpanded.
        let env = vec!["HOME=/root".to_string()];
        let args = HashMap::new();
        assert_eq!(
            interpolate_value("echo \\$SSH_AUTH_SOCK \\$HOME", &env, &args),
            "echo $SSH_AUTH_SOCK $HOME"
        );
        // Unescaped references still expand from ENV.
        assert_eq!(
            interpolate_value("\\$HOME=$HOME", &env, &args),
            "$HOME=/root"
        );
        // A lone backslash is preserved.
        assert_eq!(interpolate_value("a\\b", &env, &args), "a\\b");
    }

    #[test]
    fn registry_cache_import_fails_closed_without_metadata_layer() {
        let registry = LocalTestRegistry::run();
        let target = tempfile::tempdir().unwrap();
        let runtime = target.path().join("runtime");
        // A manifest without the cache metadata layer annotation must be
        // rejected instead of partially imported.
        let manifest = bound_manifest_json(
            &format!("sha256:{}", "5".repeat(64)),
            &format!("sha256:{}", "6".repeat(64)),
        );
        push_raw_manifest(&registry.reference("team/empty", "latest"), &manifest);
        let error = import_build_cache_from_registry(
            &runtime,
            &registry.reference("team/empty", "latest"),
            None,
        )
        .expect_err("manifest without metadata layer must fail closed");
        assert!(error.to_string().contains("no metadata layer"));
    }

    /// Push a manifest directly into the local test registry, bypassing the
    /// export path, to seed invalid fixture states.
    fn push_raw_manifest(reference: &str, manifest: &str) {
        use crate::registry::RegistryClient;
        let client = RegistryClient::new().unwrap();
        let plain = reference
            .strip_prefix("registry://")
            .expect("registry cache reference prefix");
        client
            .push_manifest_raw(plain, manifest, None)
            .expect("push fixture manifest");
    }

    #[test]
    fn registry_cache_references_are_explicit_and_descriptors_are_typed() {
        assert!(registry_cache_reference("registry://registry.example/team/cache:latest").is_ok());
        assert!(registry_cache_reference("/tmp/cache.json").is_err());
        let descriptor = registry_cache_descriptor("sha256:abc", 3, "metadata");
        assert_eq!(descriptor.media_type, OCI_IMAGE_LAYER_MEDIA_TYPE);
        assert_eq!(
            descriptor
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(REGISTRY_CACHE_KIND_ANNOTATION)),
            Some(&"metadata".to_string())
        );
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
    fn stage_dependency_graph_is_deterministic_and_rejects_forward_edges() {
        let dockerfile = r#"
        FROM scratch AS base
        RUN echo base
        FROM scratch AS independent
        RUN echo independent
        FROM scratch AS final
        COPY --from=base /out /base
        COPY --from=1 /out /independent
        "#;
        let stages = parse_stages(dockerfile).expect("stages parse");
        let graph = build_stage_dependency_graph(&stages, &HashMap::new()).expect("graph");
        assert_eq!(graph, vec![vec![], vec![], vec![0, 1]]);
        assert_eq!(
            build_stage_execution_batches(&graph).expect("batches"),
            vec![vec![0, 1], vec![2]]
        );

        let forward = parse_stages(
            "FROM scratch AS first\nCOPY --from=second /x /x\nFROM scratch AS second\n",
        )
        .expect("forward stages parse");
        let error = build_stage_dependency_graph(&forward, &HashMap::new())
            .expect_err("forward stage edge must fail");
        assert!(error.to_string().contains("earlier stage"));
        assert!(build_stage_execution_batches(&[vec![1], vec![0]]).is_err());
    }

    #[test]
    fn independent_stage_batch_executes_before_dependent_final_stage() {
        let _env = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().unwrap();
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch AS left\nCOPY left /left\nFROM scratch AS right\nCOPY right /right\nFROM scratch AS final\nCOPY --from=left /left /left\nCOPY --from=right /right /right\n",
        )
        .unwrap();
        fs::write(temp.path().join("left"), "left").unwrap();
        fs::write(temp.path().join("right"), "right").unwrap();
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).unwrap();
        let result = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/parallel:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect("parallel independent stages build");
        assert!(layer_blob_path(&runtime, &result.layer_digest).exists());
        assert!(stage_root(&runtime, 0).exists());
        assert!(stage_root(&runtime, 1).exists());
        assert!(stage_root(&runtime, 2).exists());
    }

    fn stage_identity_for(
        dockerfile: &str,
        base_digests: &[&str],
        context_digest: &str,
        compression: CompressionFormat,
    ) -> Vec<String> {
        let stages = parse_stages(dockerfile).expect("stages parse");
        let graph = build_stage_dependency_graph(&stages, &HashMap::new()).expect("graph");
        let bases = base_digests
            .iter()
            .map(|digest| digest.to_string())
            .collect::<Vec<_>>();
        stage_content_identities(&stages, &bases, context_digest, &graph, compression)
            .expect("identities")
    }

    #[test]
    fn stage_identities_are_content_addressed_per_branch() {
        let base = r#"
        FROM scratch AS base
        RUN echo base
        FROM scratch AS independent
        COPY independent /independent
        FROM scratch AS final
        COPY --from=base /out /base
        COPY --from=independent /out /independent
        "#;
        let edited_base = base.replace("RUN echo base", "RUN echo base-edited");
        let edited_independent = base.replace(
            "COPY independent /independent",
            "COPY independent /independent2",
        );
        let context = "sha256:context";
        let original = stage_identity_for(
            base,
            &["scratch", "scratch", "scratch"],
            context,
            CompressionFormat::Gzip,
        );

        // Editing stage 0 changes only stage 0 and its descendant stage 2;
        // the independent stage 1 keeps its identity.
        let after_base_edit = stage_identity_for(
            &edited_base,
            &["scratch", "scratch", "scratch"],
            context,
            CompressionFormat::Gzip,
        );
        assert_ne!(after_base_edit[0], original[0]);
        assert_eq!(after_base_edit[1], original[1]);
        assert_ne!(after_base_edit[2], original[2]);

        // Editing stage 1 changes only stage 1 and its descendant stage 2;
        // stage 0 keeps its identity.
        let after_branch_edit = stage_identity_for(
            &edited_independent,
            &["scratch", "scratch", "scratch"],
            context,
            CompressionFormat::Gzip,
        );
        assert_eq!(after_branch_edit[0], original[0]);
        assert_ne!(after_branch_edit[1], original[1]);
        assert_ne!(after_branch_edit[2], original[2]);

        // A context edit invalidates only stages that consume the context;
        // the RUN-only stage 0 is immune. A compression change invalidates
        // every stage.
        let after_context_edit = stage_identity_for(
            base,
            &["scratch", "scratch", "scratch"],
            "sha256:context-two",
            CompressionFormat::Gzip,
        );
        assert_eq!(after_context_edit[0], original[0]);
        assert_ne!(after_context_edit[1], original[1]);
        assert_ne!(after_context_edit[2], original[2]);
        let after_compression_change = stage_identity_for(
            base,
            &["scratch", "scratch", "scratch"],
            context,
            CompressionFormat::Zstd,
        );
        for (index, identity) in after_compression_change.iter().enumerate() {
            assert_ne!(*identity, original[index]);
        }

        // A base image change invalidates the stage on that base.
        let after_base_image_change = stage_identity_for(
            base,
            &["sha256:baseimage", "scratch", "scratch"],
            context,
            CompressionFormat::Gzip,
        );
        assert_ne!(after_base_image_change[0], original[0]);
        assert_eq!(after_base_image_change[1], original[1]);
    }

    #[test]
    fn worker_pool_runs_independent_stages_concurrently_within_bound() {
        let control = BuildControl {
            limits: BuildLimits::default(),
            deadline: None,
        };
        use std::sync::atomic::AtomicUsize;

        // Two stages must be executing at the same time: each waits, with a
        // bounded deadline, until the other has started. Sequential execution
        // cannot satisfy the rendezvous and fails the test instead of
        // hanging.
        let arrived = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let arrived_probe = Arc::clone(&arrived);
        let active_probe = Arc::clone(&active);
        let max_probe = Arc::clone(&max_active);
        let mut ok_results = 0usize;
        let delivered = run_stage_worker_pool(
            &[0usize, 1usize],
            2,
            &control,
            move |idx: usize| -> Result<usize, DockerfileBuildError> {
                let entered = active_probe.fetch_add(1, Ordering::SeqCst) + 1;
                max_probe.fetch_max(entered, Ordering::SeqCst);
                arrived_probe.fetch_add(1, Ordering::SeqCst);
                let deadline = Instant::now() + Duration::from_secs(5);
                while arrived_probe.load(Ordering::SeqCst) < 2 {
                    if Instant::now() >= deadline {
                        return Err(DockerfileBuildError::Invalid(
                            "stages did not run concurrently within 5s".to_string(),
                        ));
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                active_probe.fetch_sub(1, Ordering::SeqCst);
                Ok(idx)
            },
            |_, result| {
                if result.is_ok() {
                    ok_results += 1;
                }
            },
        );
        assert_eq!(delivered, 2);
        assert_eq!(ok_results, 2);
        assert_eq!(
            max_active.load(Ordering::SeqCst),
            2,
            "two permitted workers must both make progress at once"
        );

        // Six stages over two permits must never exceed two concurrent
        // executions.
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let active_probe = Arc::clone(&active);
        let max_probe = Arc::clone(&max_active);
        let mut ok_results = 0usize;
        let delivered = run_stage_worker_pool(
            &[0usize, 1, 2, 3, 4, 5],
            2,
            &control,
            move |idx: usize| -> Result<usize, DockerfileBuildError> {
                let entered = active_probe.fetch_add(1, Ordering::SeqCst) + 1;
                max_probe.fetch_max(entered, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(25));
                active_probe.fetch_sub(1, Ordering::SeqCst);
                Ok(idx)
            },
            |_, result| {
                if result.is_ok() {
                    ok_results += 1;
                }
            },
        );
        assert_eq!(delivered, 6);
        assert_eq!(ok_results, 6);
        assert!(
            max_active.load(Ordering::SeqCst) <= 2,
            "worker pool must bound concurrency to the permit count"
        );
    }

    #[test]
    fn worker_pool_fails_closed_for_cancelled_build_control() {
        let cancel_dir = tempfile::tempdir().unwrap();
        let cancel_file = cancel_dir.path().join("cancel.flag");
        fs::write(&cancel_file, b"cancel").unwrap();
        let control = BuildControl {
            limits: BuildLimits {
                cancel_file: Some(cancel_file),
                ..BuildLimits::default()
            },
            deadline: None,
        };
        let executed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let executed_probe = Arc::clone(&executed);
        let mut cancelled_results = 0usize;
        let delivered = run_stage_worker_pool(
            &[0usize, 1, 2],
            2,
            &control,
            move |idx: usize| -> Result<usize, DockerfileBuildError> {
                executed_probe.fetch_add(1, Ordering::SeqCst);
                Ok(idx)
            },
            |_, result| {
                if matches!(result, Err(DockerfileBuildError::Cancelled(_))) {
                    cancelled_results += 1;
                }
            },
        );
        assert_eq!(delivered, 3, "every queued stage must deliver a result");
        assert_eq!(cancelled_results, 3);
        assert_eq!(
            executed.load(Ordering::SeqCst),
            0,
            "no stage may execute after cancellation"
        );
    }

    /// Parse a stage trace file into (kind, stage, unix_ns, detail) rows.
    fn parse_stage_trace(path: &Path) -> Vec<(String, usize, u128, String)> {
        fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let kind = parts.next()?.to_string();
                let stage = parts.next()?.parse().ok()?;
                let timestamp = parts.next()?.parse().ok()?;
                let detail = parts.next().unwrap_or("").to_string();
                Some((kind, stage, timestamp, detail))
            })
            .collect()
    }

    /// Highest number of stages whose [start, end] trace intervals overlap.
    fn max_trace_concurrency(events: &[(String, usize, u128, String)]) -> usize {
        let mut boundaries = Vec::new();
        for (kind, _, timestamp, _) in events {
            match kind.as_str() {
                "start" => boundaries.push((*timestamp, 1i64)),
                "end" => boundaries.push((*timestamp, -1i64)),
                _ => {}
            }
        }
        boundaries.sort_unstable();
        let mut current = 0i64;
        let mut max = 0usize;
        for (_, delta) in boundaries {
            current += delta;
            max = max.max(current.unsigned_abs() as usize);
        }
        max
    }

    #[test]
    fn parallel_build_graph_execution_is_bounded_and_dependency_ordered() {
        let _env = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().unwrap();
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch AS a\nCOPY a /a\n\
             FROM scratch AS b\nCOPY b /b\n\
             FROM scratch AS c\nCOPY c /c\n\
             FROM scratch AS d\nCOPY d /d\n\
             FROM scratch AS final\nCOPY --from=a /a /a\nCOPY --from=b /b /b\nCOPY --from=c /c /c\nCOPY --from=d /d /d\n",
        )
        .unwrap();
        for name in ["a", "b", "c", "d"] {
            fs::write(temp.path().join(name), name).unwrap();
        }
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).unwrap();
        let trace = temp.path().join("stage.trace");
        std::env::set_var("FERROCRATE_BUILD_STAGE_TRACE", &trace);
        std::env::set_var("FERROCRATE_BUILD_MAX_PARALLEL_STAGES", "2");
        let outcome = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/bounded:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        );
        std::env::remove_var("FERROCRATE_BUILD_STAGE_TRACE");
        std::env::remove_var("FERROCRATE_BUILD_MAX_PARALLEL_STAGES");
        let result = outcome.expect("bounded parallel build succeeds");
        assert!(layer_blob_path(&runtime, &result.layer_digest).exists());

        let events = parse_stage_trace(&trace);
        assert!(
            events
                .iter()
                .any(|(kind, stage, _, _)| kind == "start" && *stage == 4),
            "every stage including the final one must be traced"
        );
        assert!(
            max_trace_concurrency(&events) <= 2,
            "the worker pool must never exceed the configured stage bound"
        );
        // The dependent final stage (4) may only start after every stage it
        // copies from has ended: dependency-ordered batches never overlap it.
        let final_start = events
            .iter()
            .find(|(kind, stage, _, _)| kind == "start" && *stage == 4)
            .expect("final stage start traced")
            .2;
        for stage in 0..4usize {
            let end = events
                .iter()
                .find(|(kind, other, _, _)| kind == "end" && *other == stage)
                .unwrap_or_else(|| panic!("stage {stage} end traced"))
                .2;
            assert!(
                final_start >= end,
                "dependent final stage must not run before stage {stage} completed"
            );
        }
    }

    #[test]
    fn stage_edit_invalidates_only_that_stage_and_its_descendants() {
        let _env = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().unwrap();
        let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).unwrap();
        let dockerfile = temp.path().join("Dockerfile");
        let original_dockerfile = "FROM scratch AS base\nCOPY base /base\n\
             FROM scratch AS branch\nCOPY branch /branch\n\
             FROM scratch AS final\nCOPY --from=base /base /base\nCOPY --from=branch /branch /branch\n";
        // Edit only stage 1: it copies to /branch2, and the final stage's
        // COPY --from=branch source follows so the image stays consistent.
        let edited_dockerfile = "FROM scratch AS base\nCOPY base /base\n\
             FROM scratch AS branch\nCOPY branch /branch2\n\
             FROM scratch AS final\nCOPY --from=base /base /base\nCOPY --from=branch /branch2 /branch\n";
        fs::write(&dockerfile, original_dockerfile).unwrap();
        fs::write(temp.path().join("base"), "base").unwrap();
        fs::write(temp.path().join("branch"), "branch").unwrap();
        let first = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/invalidate:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &authority,
        )
        .expect("seed build");

        // Plan-level identities: editing the branch stage leaves the base
        // stage identity untouched.
        let plan_before = prepare_dockerfile_build(
            &dockerfile,
            Some("local/invalidate:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
        )
        .unwrap();
        fs::write(&dockerfile, edited_dockerfile).unwrap();
        let plan_after = prepare_dockerfile_build(
            &dockerfile,
            Some("local/invalidate:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
        )
        .unwrap();
        assert_eq!(
            plan_after.stage_identities()[0],
            plan_before.stage_identities()[0]
        );
        assert_ne!(
            plan_after.stage_identities()[1],
            plan_before.stage_identities()[1]
        );

        let trace = temp.path().join("stage.trace");
        std::env::set_var("FERROCRATE_BUILD_STAGE_TRACE", &trace);
        let second = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/invalidate:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &authority,
        );
        std::env::remove_var("FERROCRATE_BUILD_STAGE_TRACE");
        let second = second.expect("rebuild after branch edit succeeds");
        assert_ne!(first.layer_digest, second.layer_digest);

        let events = parse_stage_trace(&trace);
        let restored = events
            .iter()
            .filter(|(kind, _, _, _)| kind == "restore")
            .map(|(_, stage, _, _)| *stage)
            .collect::<Vec<_>>();
        assert_eq!(
            restored,
            vec![0],
            "only the unchanged base stage may restore from its checkpoint"
        );
        let rebuilt = events
            .iter()
            .filter(|(kind, _, _, _)| kind == "start")
            .map(|(_, stage, _, _)| *stage)
            .filter(|stage| !restored.contains(stage))
            .collect::<Vec<_>>();
        assert_eq!(rebuilt, vec![1, 2], "edited stage and descendant rebuild");
    }

    #[test]
    fn failed_parallel_batch_journals_partial_completion_and_resumes() {
        let _env = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().unwrap();
        let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).unwrap();
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch AS left\nCOPY left /left\n\
             FROM scratch AS broken\nCOPY does-not-exist /broken\n",
        )
        .unwrap();
        fs::write(temp.path().join("left"), "left").unwrap();

        // One stage of the independent batch fails while its sibling
        // succeeds; the journal must record the sibling as completed.
        let outcome = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/resume:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &authority,
        );
        assert!(outcome.is_err(), "build with a missing COPY source fails");
        let journal = load_build_journal(&runtime)
            .unwrap()
            .expect("journal present");
        assert_eq!(journal.state, BuildJournalState::Failed);
        assert_eq!(
            journal.completed_stages,
            vec![0],
            "the parallel sibling that completed must be journaled"
        );

        // Retry with the failure fixed: stage 0 resumes from its checkpoint
        // instead of rebuilding.
        fs::write(
            &dockerfile,
            "FROM scratch AS left\nCOPY left /left\n\
             FROM scratch AS fixed\nCOPY left /fixed\n",
        )
        .unwrap();
        let trace = temp.path().join("stage.trace");
        std::env::set_var("FERROCRATE_BUILD_STAGE_TRACE", &trace);
        let result = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/resume:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &authority,
        );
        std::env::remove_var("FERROCRATE_BUILD_STAGE_TRACE");
        let result = result.expect("retry build succeeds");
        assert!(layer_blob_path(&runtime, &result.layer_digest).exists());
        let events = parse_stage_trace(&trace);
        let restored = events
            .iter()
            .filter(|(kind, _, _, _)| kind == "restore")
            .map(|(_, stage, _, _)| *stage)
            .collect::<Vec<_>>();
        assert_eq!(restored, vec![0], "retry must resume from completed stages");
        let journal = load_build_journal(&runtime)
            .unwrap()
            .expect("journal present");
        assert_eq!(journal.state, BuildJournalState::Complete);
        assert_eq!(journal.completed_stages, vec![0, 1]);
    }

    #[test]
    fn run_mount_secret_and_ssh_are_parsed_with_safe_defaults() {
        let run = parse_run(
            "--mount=type=secret,id=token echo value",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("secret mount parses");
        assert_eq!(run.secret_mounts[0].id, "token");
        assert_eq!(run.secret_mounts[0].target, "/run/secrets/token");
        assert!(!run.secret_mounts[0].required);
        assert_eq!(run.secret_mounts[0].mode, 0o400);
        assert_eq!(run.secret_mounts[0].uid, 0);
        assert_eq!(run.secret_mounts[0].gid, 0);
        let env_secret = parse_run(
            "--mount=type=secret,id=token,env=TOKEN echo value",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("secret environment mount parses");
        assert_eq!(env_secret.secret_mounts[0].env.as_deref(), Some("TOKEN"));
        let metadata = parse_run(
            "--mount=type=secret,target=/run/token,uid=1001,gid=1002,mode=0440,required cat /run/token",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("secret metadata parses");
        assert_eq!(metadata.secret_mounts[0].id, "token");
        assert_eq!(metadata.secret_mounts[0].uid, 1001);
        assert_eq!(metadata.secret_mounts[0].gid, 1002);
        assert_eq!(metadata.secret_mounts[0].mode, 0o440);
        let optional = parse_run(
            "--mount=type=secret,id=optional,required=false echo value",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("optional secret mount parses");
        assert!(!optional.secret_mounts[0].required);
        let ssh = parse_run(
            "--mount=type=ssh echo value",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("ssh mount parses");
        assert_eq!(ssh.ssh_mounts[0].id, "default");
        assert_eq!(ssh.ssh_mounts[0].target, "/run/buildkit/ssh_agent.default");
        assert!(parse_run(
            "--mount=type=secret,id=bad/slash echo value",
            &["/bin/sh".into(), "-c".into()]
        )
        .is_err());
        for invalid in [
            "--mount=type=ssh,id=bad/slash echo value",
            "--mount=type=ssh,target=relative.sock echo value",
            "--mount=type=ssh,target=/run/agent.sock --mount=type=ssh,target=/run/agent.sock echo value",
        ] {
            assert!(parse_run(invalid, &["/bin/sh".into(), "-c".into()]).is_err());
        }
        assert!(parse_run(
            "--mount=type=ssh [\"/bin/sh\",\"-c\",\"echo value\"]",
            &["/bin/sh".into(), "-c".into()]
        )
        .is_err());
        // Secret and SSH mounts resolve only against caller-provided sources;
        // an inline src= would silently imply a different provenance.
        for rejected in [
            "--mount=type=secret,id=token,src=/etc/shadow echo value",
            "--mount=type=secret,id=token,source=/etc/shadow echo value",
            "--mount=type=ssh,src=/run/host-agent.sock echo value",
        ] {
            assert!(parse_run(rejected, &["/bin/sh".into(), "-c".into()]).is_err());
        }
    }

    /// Return the host busybox path when it is a static ELF usable inside a
    /// chroot build rootfs, otherwise `None` (the caller skips the test).
    #[cfg(unix)]
    fn static_busybox() -> Option<std::path::PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        let path = std::path::PathBuf::from("/usr/bin/busybox");
        let metadata = fs::symlink_metadata(&path).ok()?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return None;
        }
        let bytes = fs::read(&path).ok()?;
        // 64-bit little-endian ELF with no PT_INTERP header => self-contained.
        if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
            return None;
        }
        let phoff = u64::from_le_bytes(bytes[32..40].try_into().ok()?) as usize;
        let phentsize = u16::from_le_bytes(bytes[54..56].try_into().ok()?) as usize;
        let phnum = u16::from_le_bytes(bytes[56..58].try_into().ok()?) as usize;
        for index in 0..phnum {
            let offset = phoff.checked_add(index.checked_mul(phentsize)?)?;
            let ptype = u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?);
            if ptype == 3 {
                return None; // PT_INTERP: dynamically linked, unusable in chroot
            }
        }
        Some(path)
    }

    #[cfg(unix)]
    fn contains_needle(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len().max(1)).any(|w| w == needle)
    }

    /// Fail when any file under `root` contains `needle` verbatim.
    #[cfg(unix)]
    fn assert_tree_free_of(root: &std::path::Path, needle: &[u8], label: &str) {
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(err) => panic!("cannot scan {}: {err}", dir.display()),
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(bytes) = fs::read(&path) {
                    assert!(
                        !contains_needle(&bytes, needle),
                        "{label} bytes leaked into {}",
                        path.display()
                    );
                    // Compressed layer blobs are decompressed before the
                    // check so the proof stays literal.
                    if bytes.starts_with(b"\x1f\x8b") {
                        let mut decoded = Vec::new();
                        let mut reader = flate2::read::GzDecoder::new(&bytes[..]);
                        if std::io::Read::read_to_end(&mut reader, &mut decoded).is_ok() {
                            assert!(
                                !contains_needle(&decoded, needle),
                                "{label} bytes leaked into decompressed {}",
                                path.display()
                            );
                        }
                    }
                }
            }
        }
    }

    /// Restores one process environment variable on drop.
    #[cfg(unix)]
    struct ScopedEnvVar {
        key: &'static str,
        old: Option<std::ffi::OsString>,
    }

    #[cfg(unix)]
    impl ScopedEnvVar {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let old = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, old }
        }
    }

    #[cfg(unix)]
    impl Drop for ScopedEnvVar {
        fn drop(&mut self) {
            match self.old.take() {
                Some(old) => std::env::set_var(self.key, old),
                None => std::env::remove_var(self.key),
            }
        }
    }

    /// True when the host refuses unprivileged user-namespace uid mapping
    /// (for example via AppArmor policy). Such hosts cannot start the RUN
    /// build sandbox at all, which is a documented host-policy limitation,
    /// not a mount defect; callers skip execution-level checks.
    #[cfg(unix)]
    fn host_blocks_rootless_build_sandbox() -> bool {
        // The sandbox uses the rootful unshare set when euid is 0 and the
        // user-namespace set otherwise; probe the one that would run.
        if !nix::unistd::Uid::effective().is_root() {
            return crate::rootless::bubblewrap_path().is_none_or(|bwrap| {
                !std::process::Command::new(bwrap)
                    .args([
                        "--unshare-user",
                        "--uid",
                        "0",
                        "--gid",
                        "0",
                        "--ro-bind",
                        "/",
                        "/",
                        "/bin/true",
                    ])
                    .status()
                    .is_ok_and(|status| status.success())
            });
        }
        let args = ["-m", "--propagation", "unchanged"];
        match std::process::Command::new("unshare")
            .args(args)
            .arg("/bin/true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        {
            Ok(status) => !status.success(),
            Err(_) => true,
        }
    }

    #[cfg(unix)]
    fn skip_unavailable_rootless_build_sandbox() -> bool {
        if !nix::unistd::Uid::effective().is_root() && !crate::rootless::bubblewrap_available() {
            eprintln!(
                "skipping: {}",
                crate::rootless::BUBBLEWRAP_UNAVAILABLE_MESSAGE
            );
            return true;
        }
        if host_blocks_rootless_build_sandbox() {
            eprintln!("skipping: host policy blocks the rootless RUN sandbox");
            return true;
        }
        false
    }

    #[cfg(unix)]
    #[test]
    fn rootless_build_namespace_maps_identity_before_private_mount() {
        if nix::unistd::Uid::effective().is_root() {
            eprintln!("skipping: rootless namespace ordering requires an unprivileged uid");
            return;
        }
        if !crate::rootless::bubblewrap_available() {
            eprintln!(
                "skipping: {}",
                crate::rootless::BUBBLEWRAP_UNAVAILABLE_MESSAGE
            );
            return;
        }
        let Some(busybox) = static_busybox() else {
            eprintln!("skipping: no static /usr/bin/busybox on this host");
            return;
        };
        let temp = tempfile::tempdir().expect("tempdir");
        let context = temp.path().join("context");
        fs::create_dir_all(&context).expect("context");
        let dockerfile = context.join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch\nCOPY busybox /busybox\nRUN [\"/busybox\", \"true\"]\n",
        )
        .expect("dockerfile");
        fs::copy(busybox, context.join("busybox")).expect("busybox");
        let runtime = temp.path().join("runtime");
        let store =
            crate::image_store::LocalImageStore::open(runtime.join("images")).expect("image store");
        super::build_from_dockerfile_with_store_and_compression_with_contexts_and_secrets(
            &dockerfile,
            Some("local/rootless-run:latest"),
            &runtime,
            crate::layer_compression::CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
            &HashMap::new(),
            &HashMap::new(),
            None,
        )
        .unwrap_or_else(|error| panic!("rootless RUN should succeed: {error}"));
    }

    #[cfg(unix)]
    #[test]
    fn rootless_run_has_network_proc_and_a_resolver() {
        if nix::unistd::Uid::effective().is_root() || skip_unavailable_rootless_build_sandbox() {
            eprintln!("skipping: rootless build networking requires an unprivileged sandbox");
            return;
        }
        let Some(busybox) = static_busybox() else {
            eprintln!("skipping: no static /usr/bin/busybox on this host");
            return;
        };
        let temp = tempfile::tempdir().expect("tempdir");
        let context = temp.path().join("context");
        fs::create_dir_all(&context).expect("context");
        let dockerfile = context.join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch\nCOPY busybox /busybox\nRUN [\"/busybox\", \"sh\", \"-c\", \"test -d /proc/net && nslookup registry.npmjs.org\"]\n",
        )
        .expect("dockerfile");
        fs::copy(busybox, context.join("busybox")).expect("busybox");
        let runtime = temp.path().join("runtime");
        let store =
            crate::image_store::LocalImageStore::open(runtime.join("images")).expect("image store");
        super::build_from_dockerfile_with_store_and_compression_with_contexts_and_secrets(
            &dockerfile,
            Some("local/rootless-network:latest"),
            &runtime,
            crate::layer_compression::CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
            &HashMap::new(),
            &HashMap::new(),
            None,
        )
        .unwrap_or_else(|error| panic!("rootless RUN needs network and /proc: {error}"));
    }

    #[cfg(unix)]
    #[test]
    fn failed_run_reports_its_command_and_stderr() {
        if skip_unavailable_rootless_build_sandbox() {
            return;
        }
        let Some(busybox) = static_busybox() else {
            eprintln!("skipping: no static /usr/bin/busybox on this host");
            return;
        };
        let temp = tempfile::tempdir().expect("tempdir");
        let context = temp.path().join("context");
        fs::create_dir_all(&context).expect("context");
        let dockerfile = context.join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch\nCOPY busybox /busybox\nRUN [\"/busybox\", \"sh\", \"-c\", \"echo step-stderr >&2; exit 23\"]\n",
        )
        .expect("dockerfile");
        fs::copy(busybox, context.join("busybox")).expect("busybox");
        let runtime = temp.path().join("runtime");
        let store =
            crate::image_store::LocalImageStore::open(runtime.join("images")).expect("image store");
        let result =
            super::build_from_dockerfile_with_store_and_compression_with_contexts_and_secrets(
                &dockerfile,
                Some("local/run-output:latest"),
                &runtime,
                crate::layer_compression::CompressionFormat::Gzip,
                &store,
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                &HashMap::new(),
                &HashMap::new(),
                None,
            );
        let error = match result {
            Ok(_) => panic!("RUN must fail"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(message.contains("step-stderr"), "error={message}");
        assert!(message.contains("exit 23"), "error={message}");
    }

    #[cfg(unix)]
    #[test]
    fn run_layer_is_a_delta_and_manifest_retains_the_context_layer() {
        if skip_unavailable_rootless_build_sandbox() {
            return;
        }
        let Some(busybox) = static_busybox() else {
            eprintln!("skipping: no static /usr/bin/busybox on this host");
            return;
        };
        let temp = tempfile::tempdir().expect("tempdir");
        let context = temp.path().join("context");
        fs::create_dir_all(&context).unwrap();
        let dockerfile = context.join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch\nCOPY busybox /bin/sh\nRUN [\"/bin/sh\", \"-c\", \"touch /marker\"]\n",
        )
        .unwrap();
        fs::copy(busybox, context.join("busybox")).unwrap();
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).unwrap();
        let result = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/run-delta:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .unwrap();
        let layers = resolve_layer_paths_with_store(&runtime, &result.reference, &store).unwrap();
        assert_eq!(layers.len(), 2, "context followed by the RUN delta");
        let decoder = flate2::read::GzDecoder::new(fs::File::open(&layers[1]).unwrap());
        let mut archive = tar::Archive::new(decoder);
        let names = archive
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().into_owned())
            .collect::<Vec<_>>();
        assert!(names.contains(&PathBuf::from("marker")));
        assert!(!names.contains(&PathBuf::from("bin/sh")));

        let root = temp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        for layer in &layers {
            crate::rootfs::apply_layer_tar(&root, layer).unwrap();
        }
        assert!(root.join("bin/sh").is_file());
        assert!(root.join("marker").is_file());
    }

    #[test]
    fn run_bracket_utility_executes_as_shell_form() {
        if skip_unavailable_rootless_build_sandbox() {
            return;
        }
        let Some(busybox) = static_busybox() else {
            eprintln!("skipping: no static /usr/bin/busybox on this host");
            return;
        };
        let temp = tempfile::tempdir().expect("tempdir");
        let context = temp.path().join("context");
        fs::create_dir_all(&context).unwrap();
        let dockerfile = context.join("Dockerfile");
        fs::write(
            &dockerfile,
            concat!(
                "FROM scratch\n",
                "COPY busybox /bin/sh\n",
                "COPY busybox /busybox\n",
                "RUN [ \"$(busybox echo shell-ran)\" == \"shell-ran\" ]\n",
                "RUN touch /shell-marker\n",
                "RUN [\"/busybox\", \"touch\", \"/exec-marker\"]\n",
            ),
        )
        .unwrap();
        fs::copy(busybox, context.join("busybox")).unwrap();
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).unwrap();
        build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/run-bracket-shell:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .unwrap_or_else(|error| panic!("bracket-utility RUN should build: {error}"));
        let layers =
            resolve_layer_paths_with_store(&runtime, "local/run-bracket-shell:latest", &store)
                .unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        for layer in &layers {
            crate::rootfs::apply_layer_tar(&root, layer).unwrap();
        }
        assert!(root.join("shell-marker").is_file(), "shell-form RUN ran");
        assert!(root.join("exec-marker").is_file(), "exec-form RUN ran");
    }

    const SECRET_NEEDLE: &[u8] = b"TEST-SECRET-DO-NOT-USE";

    #[cfg(unix)]
    #[test]
    fn secret_mount_run_sees_secret_then_all_artifacts_stay_clean() {
        let _env = crate::test_support::acquire_env_lock();
        use crate::image_store::LocalImageStore;
        use crate::layer_compression::CompressionFormat;
        let Some(busybox) = static_busybox() else {
            eprintln!("skipping: no static /usr/bin/busybox on this host");
            return;
        };
        if skip_unavailable_rootless_build_sandbox() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let ctx = temp.path().join("ctx");
        fs::create_dir_all(&ctx).expect("ctx dir");
        let dockerfile = ctx.join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch\n\
             COPY busybox /busybox\n\
             SHELL [\"/busybox\", \"sh\", \"-c\"]\n\
             RUN --mount=type=secret,id=token /busybox grep -q TEST-SECRET-DO-NOT-USE /run/secrets/token\n\
             RUN /busybox test ! -e /run/secrets/token\n",
        )
        .expect("write dockerfile");
        fs::copy(busybox, ctx.join("busybox")).expect("copy busybox");
        // The secret source lives outside the build context on purpose.
        let secret_source = temp.path().join("token.secret");
        fs::write(&secret_source, "TEST-SECRET-DO-NOT-USE\n").expect("write secret");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("open store");
        let mut secrets = HashMap::new();
        secrets.insert("token".to_string(), secret_source);
        let result =
            super::build_from_dockerfile_with_store_and_compression_with_contexts_and_secrets(
                &dockerfile,
                Some("local/secret-e2e:latest"),
                &runtime,
                CompressionFormat::Gzip,
                &store,
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                &HashMap::new(),
                &secrets,
                None,
            )
            .unwrap_or_else(|err| panic!("secret build succeeds: {err}"));
        assert!(layer_blob_path(&runtime, &result.layer_digest).exists());
        // Sensitive builds never write cache metadata or stage checkpoints.
        assert!(
            !build_cache_path(&runtime).exists(),
            "sensitive build must not write cache metadata"
        );
        assert!(
            !stage_checkpoint_path(&runtime).is_file(),
            "sensitive build must not write stage checkpoints"
        );
        // No layer, config, manifest, cache metadata, or stage rootfs file
        // carries the secret bytes.
        assert_tree_free_of(&runtime, SECRET_NEEDLE, "secret");
    }

    #[cfg(unix)]
    #[test]
    fn missing_required_secret_fails_closed_without_disclosure() {
        use crate::image_store::LocalImageStore;
        use crate::layer_compression::CompressionFormat;
        let Some(busybox) = static_busybox() else {
            eprintln!("skipping: no static /usr/bin/busybox on this host");
            return;
        };
        let temp = tempfile::tempdir().expect("tempdir");
        let ctx = temp.path().join("ctx");
        fs::create_dir_all(&ctx).expect("ctx dir");
        let dockerfile = ctx.join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch\n\
             COPY busybox /busybox\n\
             SHELL [\"/busybox\", \"sh\", \"-c\"]\n\
             RUN --mount=type=secret,id=token,required=true true\n",
        )
        .expect("write dockerfile");
        fs::copy(busybox, ctx.join("busybox")).expect("copy busybox");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("open store");
        let error =
            match super::build_from_dockerfile_with_store_and_compression_with_contexts_and_secrets(
                &dockerfile,
                Some("local/secret-missing:latest"),
                &runtime,
                CompressionFormat::Gzip,
                &store,
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                &HashMap::new(),
                &HashMap::new(),
                None,
            ) {
                Err(error) => error,
                Ok(_) => panic!("missing required secret must fail the build"),
            };
        let message = error.to_string();
        assert!(message.contains("token"), "error names the id: {message}");
        assert!(
            !message.contains("TEST-SECRET-DO-NOT-USE"),
            "error must not disclose secret material: {message}"
        );
        assert!(!build_cache_path(&runtime).exists());
    }

    #[cfg(unix)]
    #[test]
    fn optional_secret_skips_silently_when_not_provided() {
        let _env = crate::test_support::acquire_env_lock();
        use crate::image_store::LocalImageStore;
        use crate::layer_compression::CompressionFormat;
        let Some(busybox) = static_busybox() else {
            eprintln!("skipping: no static /usr/bin/busybox on this host");
            return;
        };
        if skip_unavailable_rootless_build_sandbox() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let ctx = temp.path().join("ctx");
        fs::create_dir_all(&ctx).expect("ctx dir");
        let dockerfile = ctx.join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch\n\
             COPY busybox /busybox\n\
             SHELL [\"/busybox\", \"sh\", \"-c\"]\n\
             RUN --mount=type=secret,id=absent,required=false test ! -e /run/secrets/absent\n",
        )
        .expect("write dockerfile");
        fs::copy(busybox, ctx.join("busybox")).expect("copy busybox");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("open store");
        super::build_from_dockerfile_with_store_and_compression_with_contexts_and_secrets(
            &dockerfile,
            Some("local/secret-optional:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
            &HashMap::new(),
            &HashMap::new(),
            None,
        )
        .unwrap_or_else(|err| panic!("optional absent secret builds normally: {err}"));
    }

    #[cfg(unix)]
    #[test]
    fn ssh_mount_binds_socket_and_sets_auth_sock_inside_run() {
        let _env = crate::test_support::acquire_env_lock();
        use crate::image_store::LocalImageStore;
        use crate::layer_compression::CompressionFormat;
        use std::os::unix::net::UnixListener;
        let Some(busybox) = static_busybox() else {
            eprintln!("skipping: no static /usr/bin/busybox on this host");
            return;
        };
        if skip_unavailable_rootless_build_sandbox() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let agent_dir = temp.path().join("agent");
        fs::create_dir_all(&agent_dir).expect("agent dir");
        let socket = agent_dir.join("agent.sock");
        let _listener = UnixListener::bind(&socket).expect("bind agent socket");
        let ctx = temp.path().join("ctx");
        fs::create_dir_all(&ctx).expect("ctx dir");
        let dockerfile = ctx.join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch\n\
             COPY busybox /busybox\n\
             SHELL [\"/busybox\", \"sh\", \"-c\"]\n\
             RUN --mount=type=ssh /busybox test -S \\$SSH_AUTH_SOCK && /busybox test \\$SSH_AUTH_SOCK = /run/buildkit/ssh_agent.default\n\
             RUN /busybox test ! -e /run/buildkit/ssh_agent.default\n",
        )
        .expect("write dockerfile");
        fs::copy(busybox, ctx.join("busybox")).expect("copy busybox");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("open store");
        let _guard = ScopedEnvVar::set("FERROCRATE_BUILD_SSH_AUTH_SOCK", &socket);
        super::build_from_dockerfile_with_store_and_compression_with_contexts_and_secrets(
            &dockerfile,
            Some("local/ssh-e2e:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
            &HashMap::new(),
            &HashMap::new(),
            None,
        )
        .unwrap_or_else(|err| panic!("ssh mount build succeeds: {err}"));
        assert!(
            !build_cache_path(&runtime).exists(),
            "ssh-bearing builds must not write cache metadata"
        );
        // The host agent socket path must not leak into build artifacts.
        assert_tree_free_of(
            &runtime,
            socket.as_os_str().as_encoded_bytes(),
            "socket path",
        );
    }

    #[cfg(unix)]
    #[test]
    fn authorized_secret_build_witness_journal_stays_free_of_secret_bytes() {
        use crate::authorization::gate::AuthorizationGate;
        use crate::authorization::policy::PolicyStore;
        use crate::authorization::surface::SurfaceAuthorization;
        use crate::authorization::RequestOrigin;
        use crate::image_store::LocalImageStore;
        use crate::layer_compression::CompressionFormat;
        use crate::witness::{JournalConfig, JournalMode, WitnessJournal};
        use std::sync::Arc;
        let Some(busybox) = static_busybox() else {
            eprintln!("skipping: no static /usr/bin/busybox on this host");
            return;
        };
        if skip_unavailable_rootless_build_sandbox() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let ctx = temp.path().join("ctx");
        fs::create_dir_all(&ctx).expect("ctx dir");
        let dockerfile = ctx.join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch\n\
             COPY busybox /busybox\n\
             SHELL [\"/busybox\", \"sh\", \"-c\"]\n\
             RUN --mount=type=secret,id=token /busybox grep -q TEST-SECRET-DO-NOT-USE /run/secrets/token\n",
        )
        .expect("write dockerfile");
        fs::copy(busybox, ctx.join("busybox")).expect("copy busybox");
        let secret_source = temp.path().join("token.secret");
        fs::write(&secret_source, "TEST-SECRET-DO-NOT-USE\n").expect("write secret");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("open store");
        let journal_dir = temp.path().join("journal");
        let journal = Arc::new(
            WitnessJournal::open(JournalConfig::new(
                &journal_dir,
                [0x18; 16],
                JournalMode::Required,
            ))
            .expect("open journal"),
        );
        let auth = SurfaceAuthorization::local_administrative(
            Arc::new(AuthorizationGate::new(Arc::new(
                PolicyStore::compatibility_disabled(),
            ))),
            Arc::clone(&journal),
            [0x19; 16],
        );
        let plan = prepare_dockerfile_build(
            &dockerfile,
            Some("local/secret-witness:latest"),
            &runtime,
            CompressionFormat::Gzip,
            &store,
        )
        .expect("plan");
        let permit = auth
            .authorize_image_build_plan(&RequestOrigin::cli_current().expect("origin"), &plan)
            .expect("permit");
        let mut secrets = HashMap::new();
        secrets.insert("token".to_string(), secret_source);
        super::execute_dockerfile_build_authorized_with_secrets(plan, &store, permit, &secrets)
            .unwrap_or_else(|err| panic!("authorized secret build: {err}"));
        assert!(!journal.records().expect("records").is_empty());
        assert_tree_free_of(&journal_dir, SECRET_NEEDLE, "secret");
    }

    #[cfg(unix)]
    #[test]
    fn mount_target_rejects_symlinked_rootfs_components() {
        let root = tempfile::tempdir().expect("rootfs");
        std::fs::create_dir(root.path().join("run")).expect("run");
        std::os::unix::fs::symlink("/tmp", root.path().join("run/secrets")).expect("symlink");
        let error = validate_mount_target(root.path(), "/run/secrets/token", "secret")
            .expect_err("symlinked mount target must fail closed");
        assert!(error.to_string().contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn cache_path_rejects_symlinked_intermediate_components() {
        let root = tempfile::tempdir().expect("cache root");
        std::fs::create_dir(root.path().join("private")).expect("private");
        std::os::unix::fs::symlink("/tmp", root.path().join("private/link")).expect("symlink");
        let error = reject_cache_path_symlinks(&root.path().join("private/link/cache"))
            .expect_err("symlinked cache path must fail closed");
        assert!(error
            .to_string()
            .contains("cache mount path contains a symlink"));
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
        assert_eq!(run.cache_mounts[0].sharing, CacheSharing::Shared);

        let metadata = parse_run(
            "--mount=type=cache,target=/root/.cache,id=compiler,uid=1000,gid=1001,mode=0750 echo value",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("cache metadata parses");
        assert_eq!(metadata.cache_mounts[0].uid, Some(1000));
        assert_eq!(metadata.cache_mounts[0].gid, Some(1001));
        assert_eq!(metadata.cache_mounts[0].mode, Some(0o750));

        let private = parse_run(
            "--mount=type=cache,target=/root/.cache,id=compiler,sharing=private echo value",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("private cache sharing parses");
        assert_eq!(private.cache_mounts[0].sharing, CacheSharing::Private);

        let locked = parse_run(
            "--mount=type=cache,target=/root/.cache,id=compiler,sharing=locked echo value",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("locked cache sharing parses");
        assert_eq!(locked.cache_mounts[0].sharing, CacheSharing::Locked);

        let relative = parse_run(
            "--mount=type=cache,target=relative echo value",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("relative cache target resolves against the stage workdir");
        assert_eq!(relative.cache_mounts[0].target, "/relative");

        for invalid in [
            "--mount=type=cache,target=/tmp/../escape echo value",
            "--mount=type=cache,target=/tmp,id=bad/slash echo value",
            "--mount=type=cache,target=/tmp,source=seed echo value",
            "--mount=type=cache,target=/tmp,readonly echo value",
            "--mount=type=cache,target=/tmp,uid=bad echo value",
            "--mount=type=cache,target=/tmp,mode=0999 echo value",
        ] {
            assert!(parse_run(invalid, &["/bin/sh".into(), "-c".into()]).is_err());
        }
    }

    #[test]
    fn run_mount_rejects_unsupported_sharing_and_invalid_required_options() {
        let invalid = parse_run(
            "--mount=type=cache,target=/root/.cache,sharing= true",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect_err("empty cache sharing must fail closed");
        assert!(invalid.to_string().contains("sharing requires a value"));

        let secret = parse_run(
            "--mount=type=secret,id=token,required=maybe cat /run/secrets/token",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect_err("invalid required values must fail closed");
        assert!(secret.to_string().contains("true or false"));
    }

    #[test]
    fn run_rejects_misspelled_mount_flag_before_shell_execution() {
        let error = parse_run(
            "--mont=type=tmpfs,target=/tmp true",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect_err("BuildKit rejects an unknown RUN option during parsing");
        assert!(error.to_string().contains("unknown flag: --mont"));
        assert!(error.to_string().contains("did you mean mount?"));
    }

    #[test]
    fn tmpfs_mounts_are_accepted_for_shell_runs() {
        let run = parse_run(
            "--mount=type=tmpfs,target=/tmp,size=65536 echo value",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("tmpfs mount parses");
        assert_eq!(run.tmpfs_mounts.len(), 1);
        assert_eq!(run.tmpfs_mounts[0].target, "/tmp");
        assert_eq!(run.tmpfs_mounts[0].size, Some(65_536));
        assert!(!run.tmpfs_mounts[0].read_only);
        let human_size = parse_run(
            "--mount=type=tmpfs,target=/dev/shm,size=128m echo value",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("BuildKit byte-size syntax parses");
        assert_eq!(human_size.tmpfs_mounts[0].size, Some(128 * 1024 * 1024));
        let read_only = parse_run(
            "--mount=type=tmpfs,target=/run,size=4096,ro echo value",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("read-only tmpfs mount parses");
        assert!(read_only.tmpfs_mounts[0].read_only);
        for invalid in [
            "--mount=type=tmpfs,target=relative echo value",
            "--mount=type=tmpfs,target=/tmp,size=0 echo value",
            "--mount=type=tmpfs,target=/tmp,tmpfs-size=4096 echo value",
            "--mount=type=tmpfs,target=/tmp --mount=type=tmpfs,target=/tmp echo value",
        ] {
            assert!(parse_run(invalid, &["/bin/sh".into(), "-c".into()]).is_err());
        }
    }

    #[test]
    fn run_network_mode_is_parsed_as_instruction_metadata() {
        let none = parse_run(
            "--network=none echo isolated",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("per-RUN network parses");
        assert_eq!(none.network, Some(super::DockerfileNetworkMode::None));
        assert_eq!(none.args.last().map(String::as_str), Some("echo isolated"));

        let invalid = parse_run(
            "--network=invalid true",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect_err("unknown network mode fails before execution");
        assert!(invalid.to_string().contains("invalid network mode"));
    }

    #[test]
    fn run_security_mode_is_parsed_as_instruction_metadata() {
        let insecure = parse_run(
            "--security=insecure echo privileged",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("per-RUN security mode parses");
        assert_eq!(insecure.security, super::DockerfileSecurityMode::Insecure);
        assert_eq!(
            insecure.args.last().map(String::as_str),
            Some("echo privileged"),
            "the Dockerfile flag must not reach the RUN shell",
        );

        let sandbox = parse_run(
            "--security=sandbox echo confined",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect("explicit sandbox mode parses");
        assert_eq!(sandbox.security, super::DockerfileSecurityMode::Sandbox);
        assert_eq!(
            sandbox.args.last().map(String::as_str),
            Some("echo confined"),
        );

        let invalid = parse_run(
            "--security=privileged true",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect_err("unknown security mode fails before execution");
        assert!(invalid
            .to_string()
            .contains("security \"privileged\" is not valid"));
    }

    #[test]
    fn shell_run_preserves_quoted_tabs_after_frontend_flags() {
        let command =
            "--security=sandbox [ \"CapBnd:\t00000000a80425fb\" = \"CapBnd:\t00000000a80425fb\" ]";
        let run = parse_run(command, &["/bin/sh".into(), "-c".into()]).expect("shell RUN parses");
        assert_eq!(
            run.args.last().map(String::as_str),
            Some("[ \"CapBnd:\t00000000a80425fb\" = \"CapBnd:\t00000000a80425fb\" ]")
        );
    }

    #[test]
    fn direct_root_authority_rejects_root_mapped_user_namespace() {
        assert!(super::uid_map_has_initial_namespace_root(
            "         0          0 4294967295\n"
        ));
        assert!(!super::uid_map_has_initial_namespace_root(
            "         0       1000          1\n"
        ));
        assert!(!super::uid_map_has_initial_namespace_root(
            "0 1000 1\n1 100000 65535\n"
        ));
    }

    #[test]
    fn only_none_network_uses_an_empty_build_namespace() {
        assert!(super::should_isolate_build_network(
            super::DockerfileNetworkMode::None
        ));
        assert!(!super::should_isolate_build_network(
            super::DockerfileNetworkMode::Sandbox
        ));
        assert!(!super::should_isolate_build_network(
            super::DockerfileNetworkMode::Host
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn completed_run_terminates_background_processes_holding_output_pipes() {
        use std::os::unix::process::CommandExt;

        let started = std::time::Instant::now();
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30 &"])
            .stdout(std::process::Stdio::piped());
        unsafe {
            command.pre_exec(super::create_build_process_group);
        }
        let mut child = command.spawn().expect("spawn process-group probe");
        let mut output = child.stdout.take().expect("captured stdout");
        child.wait().expect("shell exits without waiting for background job");
        super::terminate_build_process_group(child.id());
        let mut captured = Vec::new();
        std::io::Read::read_to_end(&mut output, &mut captured)
            .expect("background output pipe closes after process-group cleanup");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "background process must not hold RUN output capture open"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn insecure_device_census_matches_buildkit_fixed_and_loop_whitelist() {
        use nix::sys::stat::SFlag;
        let devices = super::buildkit_insecure_device_nodes(Some(12));
        for (path, major, minor) in [
            ("kmsg", 1, 11),
            ("cuse", 10, 203),
            ("fuse", 10, 229),
            ("kvm", 10, 232),
            ("net/tun", 10, 200),
            ("loop-control", 10, 237),
        ] {
            assert!(
                devices.iter().any(|device| {
                    device.path == std::path::Path::new(path)
                        && device.kind == SFlag::S_IFCHR
                        && device.major == major
                        && device.minor == minor
                }),
                "missing BuildKit automatic device /dev/{path}"
            );
        }
        let loops = devices
            .iter()
            .filter(|device| device.kind == SFlag::S_IFBLK && device.major == 7)
            .collect::<Vec<_>>();
        assert_eq!(loops.len(), 20, "loop whitelist must cover 0..=free+7");
        assert_eq!(loops.first().unwrap().path, std::path::Path::new("loop0"));
        assert_eq!(loops.last().unwrap().path, std::path::Path::new("loop19"));
        let fallback = super::buildkit_insecure_device_nodes(None);
        assert!(fallback
            .iter()
            .any(|device| device.path == std::path::Path::new("loop7")));
        assert!(!fallback
            .iter()
            .any(|device| device.path == std::path::Path::new("loop8")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "root-gated qualification scenario: FERROCRATE_QUAL_ROOT=1 as root"]
    fn qual_root_buildkit_insecure_devices_and_loop_whitelist() {
        assert!(
            nix::unistd::Uid::effective().is_root(),
            "root required; run via scripts/qualification-fault-matrix.sh with FERROCRATE_QUAL_ROOT=1"
        );
        let busybox = static_busybox().expect("qualification host needs static busybox");
        let free_loop = super::next_free_loop_device().unwrap_or(0);
        let last_loop = free_loop.saturating_add(7);
        let outside_loop = last_loop.saturating_add(1);
        let temp = tempfile::tempdir().expect("qualification tempdir");
        let context = temp.path().join("context");
        std::fs::create_dir_all(&context).expect("context dir");
        std::fs::copy(busybox, context.join("busybox")).expect("copy static busybox");
        let insecure_probe = format!(
            "test -c /dev/kmsg && test -c /dev/cuse && test -c /dev/fuse && \
             test -c /dev/kvm && test -c /dev/net/tun && test -c /dev/loop-control && \
             test -b /dev/loop0 && test -b /dev/loop{last_loop} && \
             test ! -e /dev/loop{outside_loop} && \
             dd if=/dev/zero of=/disk.img bs=1M count=1 >/dev/null 2>&1 && \
             losetup /dev/loop{free_loop} /disk.img && \
             losetup -d /dev/loop{free_loop} && rm /disk.img"
        );
        let insecure_json =
            serde_json::to_string(&vec!["/busybox", "sh", "-ec", insecure_probe.as_str()])
                .expect("probe JSON");
        let dockerfile = context.join("Dockerfile");
        std::fs::write(&dockerfile, format!(
            "FROM scratch\nCOPY busybox /busybox\n\
             RUN [\"/busybox\",\"sh\",\"-ec\",\"test ! -e /dev/fuse && test ! -e /dev/loop-control\"]\n\
             RUN --security=insecure {insecure_json}\n"
        )).expect("write Dockerfile");
        let runtime = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime.join("images")).expect("image store");
        let options = super::DockerfileExecutionOptions {
            allow_security_insecure: true,
            ..super::DockerfileExecutionOptions::default()
        };
        super::build_from_dockerfile_with_store_and_compression_with_contexts_and_secrets_and_build_args(
            &dockerfile, Some("local/s159-insecure-devices:latest"), &runtime,
            CompressionFormat::Gzip, &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
            &HashMap::new(), &HashMap::new(), None, &HashMap::new(), &options,
        ).unwrap_or_else(|error| panic!("rootful insecure device build failed: {error}"));
    }

    #[test]
    fn sandbox_capability_set_matches_docker_default() {
        let names = super::dockerfile_default_capabilities()
            .into_iter()
            .map(|capability| format!("{capability:?}"))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "CAP_CHOWN",
                "CAP_DAC_OVERRIDE",
                "CAP_FOWNER",
                "CAP_FSETID",
                "CAP_KILL",
                "CAP_SETGID",
                "CAP_SETUID",
                "CAP_SETPCAP",
                "CAP_NET_BIND_SERVICE",
                "CAP_NET_RAW",
                "CAP_SYS_CHROOT",
                "CAP_MKNOD",
                "CAP_AUDIT_WRITE",
                "CAP_SETFCAP",
            ]
        );
    }

    #[test]
    fn no_cache_filters_apply_to_all_or_named_stages() {
        let stages = parse_stages("FROM scratch AS build\nFROM scratch AS package\n")
            .expect("stages parse");
        let all = super::DockerfileExecutionOptions {
            no_cache: Some(Vec::new()),
            ..Default::default()
        };
        assert!(super::stage_ignores_cache(&stages[0], &all));
        assert!(super::stage_ignores_cache(&stages[1], &all));

        let named = super::DockerfileExecutionOptions {
            no_cache: Some(vec!["build".to_string()]),
            ..Default::default()
        };
        assert!(super::stage_ignores_cache(&stages[0], &named));
        assert!(!super::stage_ignores_cache(&stages[1], &named));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_cgroup_parent_accepts_docker_absolute_cgroupfs_path() {
        let temp = tempfile::tempdir().expect("cgroup root");
        fs::write(temp.path().join("cgroup.controllers"), "").expect("v2 marker");
        let _guard = ScopedEnvVar::set("FERROCRATE_CGROUP_ROOT", temp.path());
        let options = super::DockerfileExecutionOptions {
            cgroup_parent: Some("/docker-builds".to_string()),
            ..Default::default()
        };

        let group = super::prepare_build_run_cgroup(&options, 7)
            .expect("Docker accepts an absolute cgroupfs parent")
            .expect("cgroup parent requests a RUN leaf");
        assert!(group.path.starts_with(temp.path().join("docker-builds")));
        group.cleanup().expect("remove RUN leaf");
    }

    #[test]
    fn run_mount_diagnostics_suggest_buildkit_keys_and_types() {
        let key = parse_run(
            "--mount=typ=tmpfs true",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect_err("misspelled key");
        assert!(key.to_string().contains("unexpected key 'typ'"));
        assert!(key.to_string().contains("did you mean type?"));

        let kind = parse_run(
            "--mount=type=tmp true",
            &["/bin/sh".into(), "-c".into()],
        )
        .expect_err("misspelled type");
        assert!(kind.to_string().contains("unsupported mount type \"tmp\""));
        assert!(kind.to_string().contains("did you mean tmpfs?"));

        for (run, expected, suggestion) in [
            (
                "--mout=type=tmpfs,target=/tmp true",
                "unknown flag: --mout",
                Some("did you mean mount?"),
            ),
            (
                "--banana=value true",
                "unknown flag: --banana",
                None,
            ),
            (
                "--mount=type=tmpfs,targe=/tmp true",
                "unexpected key 'targe' in 'targe=/tmp'",
                Some("did you mean target?"),
            ),
            (
                "--mount=type=secre,target=/run/secret true",
                "unsupported mount type \"secre\"",
                Some("did you mean secret?"),
            ),
            (
                "--mount=type=cache,target=/tmp,sharing=lockd true",
                "unsupported sharing value \"lockd\"",
                Some("did you mean locked?"),
            ),
        ] {
            let error = parse_run(run, &["/bin/sh".into(), "-c".into()])
                .expect_err("invalid RUN option must fail during parsing");
            let message = error.to_string();
            assert!(message.contains(expected), "{message:?}");
            match suggestion {
                Some(suggestion) => assert!(message.contains(suggestion), "{message:?}"),
                None => assert!(!message.contains("did you mean"), "{message:?}"),
            }
        }
    }

    #[test]
    fn bind_mounts_are_accepted_for_shell_runs() {
        assert!(parse_run(
            "--mount=type=bind,source=assets,target=/mnt,ro echo value",
            &["/bin/sh".into(), "-c".into()]
        )
        .is_ok());
    }

    #[test]
    fn copy_chown_numeric_owner_is_accepted() {
        let stages = parse_stages("FROM scratch\nCOPY --chown=1000:1001 app /app\n").unwrap();
        assert_eq!(
            stages[0].copy_paths[0].owner,
            Some(CopyOwner::Numeric(1000, 1001))
        );
        assert_eq!(
            parse_stages("FROM scratch\nCOPY --chown=builder:staff app /app\n").unwrap()[0]
                .copy_paths[0]
                .owner,
            Some(CopyOwner::Named {
                user: "builder".into(),
                group: Some("staff".into())
            })
        );
    }

    #[test]
    fn copy_chown_names_resolve_against_base_rootfs_accounts() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc")).unwrap();
        std::fs::write(
            root.path().join("etc/passwd"),
            "builder:x:1000:1001::/home/builder:/bin/sh\n",
        )
        .unwrap();
        std::fs::write(root.path().join("etc/group"), "staff:x:2000:\n").unwrap();
        let owner = CopyOwner::Named {
            user: "builder".into(),
            group: Some("staff".into()),
        };
        assert_eq!(
            resolve_copy_owner(root.path(), &owner).unwrap(),
            (1000, 2000)
        );
        let missing = CopyOwner::Named {
            user: "missing".into(),
            group: None,
        };
        assert!(resolve_copy_owner(root.path(), &missing).is_err());
    }

    #[test]
    fn copy_from_chown_is_parsed_and_retains_owner_spec() {
        let stages = parse_stages(
            "FROM scratch AS base\nCOPY source /out\nFROM scratch\nCOPY --from=base --chown=1000:1001 /out /app\n",
        )
        .unwrap();
        assert_eq!(
            stages[1].copy_from[0].owner,
            Some(CopyOwner::Numeric(1000, 1001))
        );
    }

    #[test]
    fn add_checksum_is_strictly_validated_and_copy_rejects_it() {
        let digest = "a".repeat(64);
        let stages = parse_stages(&format!(
            "FROM scratch\nADD --checksum=sha256:{digest} https://example.test/a.tar /app\n"
        ))
        .unwrap();
        assert_eq!(stages[0].copy_paths[0].checksum, Some(digest.clone()));
        assert!(parse_stages(
            "FROM scratch\nADD --checksum=sha1:abcd https://example.test/a /app\n"
        )
        .is_err());
        assert!(parse_stages(&format!(
            "FROM scratch\nCOPY --checksum=sha256:{digest} app /app\n"
        ))
        .is_err());
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
        let parents = parse_stages("FROM scratch\nCOPY --parents src/app /opt\n").unwrap();
        assert!(parents[0].copy_paths[0].parents);
        let excludes =
            parse_stages("FROM scratch\nCOPY --exclude=*.tmp --exclude secret src /opt\n").unwrap();
        assert_eq!(excludes[0].copy_paths[0].excludes, ["*.tmp", "secret"]);
        let directive = "COPY --exclude= app /app";
        let error = parse_stages(&format!("FROM scratch\n{directive}\n"))
            .expect_err("empty exclude pattern must fail");
        assert!(error.to_string().contains("COPY --exclude"));

        let numeric_owner = parse_stages("FROM scratch\nCOPY --chown=1000:1000 app /app\n")
            .expect("numeric COPY --chown must parse");
        assert_eq!(
            numeric_owner[0].copy_paths[0].owner,
            Some(CopyOwner::Numeric(1000, 1000))
        );
        let named = parse_stages("FROM scratch\nCOPY --chown=builder app /app\n")
            .expect("named COPY --chown must parse");
        assert!(matches!(
            named[0].copy_paths[0].owner,
            Some(CopyOwner::Named { .. })
        ));

        let error = parse_stages("FROM scratch\nCOPY --chmod=999 app /app\n")
            .expect_err("invalid modes must be rejected");
        assert!(error.to_string().contains("invalid COPY --chmod mode"));
    }

    #[test]
    fn copy_link_flag_is_accepted_for_layer_isolated_materialization() {
        let stages = parse_stages("FROM scratch\nCOPY --link app /app\n").unwrap();
        assert_eq!(stages[0].copy_paths[0].srcs, vec!["app"]);
        assert_eq!(stages[0].copy_paths[0].dest, "/app");
    }

    #[test]
    fn from_platform_is_host_bound_and_rejects_ignored_tokens() {
        let host_arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "x86" => "386",
            "arm" => "arm",
            other => other,
        };
        let stages = parse_stages(&format!(
            "FROM --platform=linux/{host_arch} alpine AS base\n"
        ))
        .expect("host platform should parse");
        assert_eq!(stages[0].base, "alpine");
        assert_eq!(stages[0].name.as_deref(), Some("base"));

        let unsupported = parse_stages("FROM --platform=windows/amd64 alpine\n")
            .expect_err("non-Linux platform must fail closed");
        assert!(unsupported.to_string().contains("only linux host output"));

        let trailing = parse_stages("FROM alpine unexpected tokens\n")
            .expect_err("ignored FROM tokens must fail deterministically");
        assert!(trailing.to_string().contains("optional AS stage name"));
    }

    #[test]
    fn line_continuation_joins_wrapped_instructions() {
        let stages = parse_stages("FROM scratch\nRUN echo one && \\\n    echo two\n")
            .expect("continued RUN should join into one instruction");
        assert_eq!(stages[0].run.len(), 1);
        assert_eq!(
            stages[0].run[0].args.last().map(String::as_str),
            Some("echo one && echo two")
        );

        let copied = parse_stages("FROM scratch\nCOPY app \\\n    /app\n")
            .expect("continued COPY should join into one instruction");
        assert_eq!(copied[0].copy_paths[0].srcs, vec!["app"]);
        assert_eq!(copied[0].copy_paths[0].dest, "/app");

        let trailing = parse_stages("FROM scratch\nRUN echo hi \\")
            .expect_err("dangling continuation must fail deterministically");
        assert!(trailing.to_string().contains("ends with an escape"));
    }

    #[test]
    fn run_bracket_utility_falls_back_to_shell_form() {
        let stages = parse_stages("FROM scratch\nRUN [ \"$(command)\" == \"value\" ]\n")
            .expect("POSIX [ utility RUN should parse as shell form");
        let run = &stages[0].run[0];
        assert!(run._shell, "bracket-utility RUN must stay shell form");
        assert_eq!(
            run.args,
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "[ \"$(command)\" == \"value\" ]".to_string()
            ]
        );

        let entrypoint = parse_stages("FROM scratch\nENTRYPOINT [ \"$(command)\" == \"value\" ]\n")
            .expect("POSIX [ utility ENTRYPOINT should parse as shell form");
        assert_eq!(
            entrypoint[0].entrypoint,
            Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "[ \"$(command)\" == \"value\" ]".to_string()
            ])
        );
    }

    #[test]
    fn run_json_array_still_parses_as_exec_form() {
        let stages = parse_stages("FROM scratch\nRUN [\"echo\", \"hi\"]\n")
            .expect("JSON-array RUN should stay exec form");
        let run = &stages[0].run[0];
        assert!(!run._shell, "valid JSON-array RUN must stay exec form");
        assert_eq!(run.args, vec!["echo".to_string(), "hi".to_string()]);
    }

    #[test]
    fn escape_directive_changes_the_continuation_character() {
        let stages = parse_stages("# escape=`\nFROM scratch\nRUN echo one && `\n    echo two\n")
            .expect("backtick escape directive should be honored");
        assert_eq!(stages[0].run.len(), 1);
        assert_eq!(
            stages[0].run[0].args.last().map(String::as_str),
            Some("echo one && echo two")
        );

        let backslash_literal =
            parse_stages("# escape=`\nFROM scratch\nRUN echo one && \\\necho two\n")
                .expect_err("backslash must not continue lines under escape directive");
        assert!(backslash_literal.to_string().contains("ECHO"));
    }

    #[test]
    fn syntax_directive_is_consumed_before_dockerfile_instructions() {
        let stages = parse_stages("# syntax=docker/dockerfile:1\nFROM alpine:3.20\n")
            .expect("syntax directive must not become an instruction");
        assert_eq!(stages.len(), 1);
        assert_eq!(stages[0].base, "alpine:3.20");
    }

    #[test]
    fn invalid_escape_directive_is_rejected() {
        let error = parse_stages("# escape=ab\nFROM scratch\n")
            .expect_err("multi-character escape directive must fail");
        assert!(error.to_string().contains("escape"));

        let error = parse_stages("# escape=\nFROM scratch\n")
            .expect_err("empty escape directive must fail");
        assert!(error.to_string().contains("escape"));
    }

    #[test]
    fn unknown_leading_comment_directives_stay_comments() {
        let stages = parse_stages("# unknown-key=value\nFROM scratch\nLABEL a=b\n")
            .expect("unknown directives remain comments like Docker");
        assert_eq!(stages[0].labels.get("a").map(String::as_str), Some("b"));
    }

    #[test]
    fn unsupported_directives_fail_instead_of_being_silently_ignored() {
        assert_eq!(
            parse_stages("FROM scratch\nSTOPSIGNAL SIGTERM\n").unwrap()[0]
                .stop_signal
                .as_deref(),
            Some("SIGTERM")
        );
        assert_eq!(
            parse_stages("FROM scratch\nMAINTAINER legacy\n").unwrap()[0]
                .author
                .as_deref(),
            Some("legacy")
        );
        assert_eq!(
            parse_stages("FROM scratch\nONBUILD RUN echo hi\n").unwrap()[0].onbuild,
            ["RUN echo hi"]
        );
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
                owner: None,
                checksum: None,
                parents: false,
                excludes: Vec::new(),
                extract_archives: false,
                inline_content: None,
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
    fn copy_parents_preserves_source_path() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = temp.path().join("src").join("app");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(source_dir.join("main.txt"), "main").unwrap();
        let destination = temp.path().join("destination");
        super::copy_from_context(
            temp.path(),
            &destination,
            &[super::CopySpec {
                srcs: vec!["src/app/main.txt".into()],
                dest: "/opt".into(),
                chmod: None,
                owner: None,
                checksum: None,
                parents: true,
                excludes: Vec::new(),
                extract_archives: false,
                inline_content: None,
            }],
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(destination.join("opt/src/app/main.txt")).unwrap(),
            "main"
        );

        let error = super::copy_from_context(
            temp.path(),
            &destination,
            &[super::CopySpec {
                srcs: vec!["../escape.txt".into()],
                dest: "/opt".into(),
                chmod: None,
                owner: None,
                checksum: None,
                parents: true,
                excludes: Vec::new(),
                extract_archives: false,
                inline_content: None,
            }],
        )
        .expect_err("parent traversal must be rejected");
        assert!(error.to_string().contains("parent traversal"));
    }

    #[test]
    fn copy_exclude_filters_matching_files_and_directories() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::write(source.join("keep.txt"), "keep").unwrap();
        std::fs::write(source.join("skip.tmp"), "skip").unwrap();
        std::fs::write(source.join("nested").join("secret"), "secret").unwrap();
        let destination = temp.path().join("destination");
        super::copy_from_context(
            temp.path(),
            &destination,
            &[super::CopySpec {
                srcs: vec!["source".into()],
                dest: "/app".into(),
                chmod: None,
                owner: None,
                checksum: None,
                parents: false,
                excludes: vec!["*.tmp".into(), "secret".into()],
                extract_archives: false,
                inline_content: None,
            }],
        )
        .unwrap();
        assert!(destination.join("app/keep.txt").exists());
        assert!(!destination.join("app/skip.tmp").exists());
        assert!(!destination.join("app/nested/secret").exists());

        let explicit_destination = temp.path().join("explicit-destination");
        super::copy_from_context(
            temp.path(),
            &explicit_destination,
            &[super::CopySpec {
                srcs: vec!["source/skip.tmp".into()],
                dest: "/app".into(),
                chmod: None,
                owner: None,
                checksum: None,
                parents: false,
                excludes: vec!["*.tmp".into()],
                extract_archives: false,
                inline_content: None,
            }],
        )
        .unwrap();
        assert!(!explicit_destination.join("app/skip.tmp").exists());
    }

    #[test]
    fn copy_context_io_errors_name_the_source_path() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("node_modules/cors");
        let error = super::copy_from_context(
            temp.path(),
            &temp.path().join("destination"),
            &[super::CopySpec {
                srcs: vec!["node_modules/cors".into()],
                dest: "/cors".into(),
                chmod: None,
                owner: None,
                checksum: None,
                parents: false,
                excludes: Vec::new(),
                extract_archives: false,
                inline_content: None,
            }],
        )
        .expect_err("a missing COPY source must fail");
        assert!(
            error.to_string().contains(&missing.display().to_string()),
            "COPY error must identify the source path: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn copy_preserves_relative_and_dangling_symlinks() {
        use std::os::unix::fs::symlink;
        use std::path::PathBuf;

        let temp = tempfile::tempdir().unwrap();
        let bin = temp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(temp.path().join("real.txt"), "real").unwrap();
        symlink("../real.txt", bin.join("link")).unwrap();
        symlink("../missing.txt", bin.join("dangling")).unwrap();
        let destination = temp.path().join("destination");
        super::copy_from_context(
            temp.path(),
            &destination,
            &[super::CopySpec {
                srcs: vec!["bin".into()],
                dest: "/bin".into(),
                chmod: None,
                owner: None,
                checksum: None,
                parents: false,
                excludes: Vec::new(),
                extract_archives: false,
                inline_content: None,
            }],
        )
        .unwrap();
        assert_eq!(
            fs::read_link(destination.join("bin/link")).unwrap(),
            PathBuf::from("../real.txt")
        );
        assert_eq!(
            fs::read_link(destination.join("bin/dangling")).unwrap(),
            PathBuf::from("../missing.txt")
        );
    }

    #[test]
    fn add_extracts_tar_gzip_bzip_and_xz_archives_without_path_escape() {
        use bzip2::{write::BzEncoder, Compression as BzCompression};
        use flate2::{write::GzEncoder, Compression};
        use lzma_rust2::{XzOptions, XzWriter};
        use std::io::{Cursor, Write};

        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("payload.tar");
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_path("nested/payload.txt").unwrap();
            header.set_size(7);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, Cursor::new(b"payload")).unwrap();
            builder.finish().unwrap();
        }
        fs::write(&archive_path, &bytes).unwrap();
        let gzip_path = temp.path().join("payload.tar.gz");
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&bytes).unwrap();
        fs::write(&gzip_path, encoder.finish().unwrap()).unwrap();
        let bzip_path = temp.path().join("payload.tar.bz2");
        let mut encoder = BzEncoder::new(Vec::new(), BzCompression::default());
        encoder.write_all(&bytes).unwrap();
        fs::write(&bzip_path, encoder.finish().unwrap()).unwrap();
        let xz_path = temp.path().join("payload.tar.xz");
        let mut encoder = XzWriter::new(Vec::new(), XzOptions::default()).unwrap();
        encoder.write_all(&bytes).unwrap();
        fs::write(&xz_path, encoder.finish().unwrap()).unwrap();

        let stages = parse_stages("FROM scratch\nADD --chmod=600 payload.tar /app\n").unwrap();
        assert!(stages[0].copy_paths[0].extract_archives);
        assert_eq!(stages[0].copy_paths[0].chmod, Some(0o600));
        let destination = temp.path().join("destination");
        super::copy_from_context(
            temp.path(),
            &destination,
            &[super::CopySpec {
                srcs: vec![
                    "payload.tar".into(),
                    "payload.tar.gz".into(),
                    "payload.tar.bz2".into(),
                    "payload.tar.xz".into(),
                ],
                dest: "/app".into(),
                chmod: Some(0o600),
                owner: None,
                checksum: None,
                parents: false,
                excludes: Vec::new(),
                extract_archives: true,
                inline_content: None,
            }],
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(destination.join("app/nested/payload.txt")).unwrap(),
            "payload"
        );
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(
                &fs::metadata(destination.join("app/nested/payload.txt"))
                    .unwrap()
                    .permissions()
            ) & 0o777,
            0o600
        );

        let escape_path = temp.path().join("escape.tar");
        let mut escape = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path("escape.txt").unwrap();
        header.as_mut_bytes()[..14].fill(0);
        header.as_mut_bytes()[..14].copy_from_slice(b"../escape.txt\0");
        header.set_size(6);
        header.set_cksum();
        escape.append(&header, Cursor::new(b"escape")).unwrap();
        fs::write(escape_path, escape.into_inner().unwrap()).unwrap();
        let error = super::copy_from_context(
            temp.path(),
            &temp.path().join("safe"),
            &[super::CopySpec {
                srcs: vec!["escape.tar".into()],
                dest: "/app".into(),
                chmod: None,
                owner: None,
                checksum: None,
                parents: false,
                excludes: Vec::new(),
                extract_archives: true,
                inline_content: None,
            }],
        )
        .expect_err("ADD archive traversal must fail closed");
        assert!(error.to_string().contains("escapes destination"));
    }

    #[test]
    fn add_fetches_bounded_remote_archive_and_uses_url_basename() {
        use httptest::responders::status_code;
        use httptest::{Expectation, Server};
        use std::io::Cursor;

        let temp = tempfile::tempdir().unwrap();
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_path("remote/payload.txt").unwrap();
            header.set_size(6);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, Cursor::new(b"remote")).unwrap();
            builder.finish().unwrap();
        }
        let server = Server::run();
        server.expect(
            Expectation::matching(httptest::matchers::request::method_path(
                "GET",
                "/payload.tar",
            ))
            .respond_with(status_code(200).body(bytes)),
        );
        let destination = temp.path().join("destination");
        super::copy_from_context(
            temp.path(),
            &destination,
            &[super::CopySpec {
                srcs: vec![format!(
                    "{}/payload.tar?cache=1",
                    server.url_str("").trim_end_matches('/')
                )],
                dest: "/app/".into(),
                chmod: None,
                owner: None,
                checksum: None,
                parents: false,
                excludes: Vec::new(),
                extract_archives: true,
                inline_content: None,
            }],
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(destination.join("app/remote/payload.txt")).unwrap(),
            "remote"
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

    fn write_minimal_build_fixture(
        temp: &std::path::Path,
    ) -> (std::path::PathBuf, std::path::PathBuf, LocalImageStore) {
        let dockerfile = temp.join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\nCOPY . /\n").unwrap();
        fs::write(temp.join("hello.txt"), "fixture").unwrap();
        let runtime_dir = temp.join("runtime");
        let store = LocalImageStore::open(runtime_dir.join("images")).unwrap();
        (dockerfile, runtime_dir, store)
    }

    #[test]
    fn build_control_fails_closed_for_cancel_file_and_deadline() {
        let control = BuildControl {
            limits: BuildLimits::default(),
            deadline: None,
        };
        assert!(control.check("test").is_ok());

        let cancel_dir = tempfile::tempdir().unwrap();
        let cancel_file = cancel_dir.path().join("cancel.flag");
        fs::write(&cancel_file, b"cancel").unwrap();
        let control = BuildControl {
            limits: BuildLimits {
                cancel_file: Some(cancel_file),
                ..BuildLimits::default()
            },
            deadline: None,
        };
        assert!(matches!(
            control.check("test"),
            Err(DockerfileBuildError::Cancelled(_))
        ));

        let control = BuildControl {
            limits: BuildLimits::default(),
            deadline: Some(std::time::Instant::now()),
        };
        assert!(matches!(
            control.check("test"),
            Err(DockerfileBuildError::LimitExceeded(_))
        ));
    }

    #[test]
    fn cancelled_build_is_journaled_and_never_publishes() {
        let _env = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().unwrap();
        let (dockerfile, runtime_dir, store) = write_minimal_build_fixture(temp.path());
        let cancel_file = temp.path().join("cancel.flag");
        fs::write(&cancel_file, b"cancel").unwrap();
        std::env::set_var("FERROCRATE_BUILD_CANCEL_FILE", &cancel_file);
        let outcome = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/cancel:latest"),
            &runtime_dir,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        );
        std::env::remove_var("FERROCRATE_BUILD_CANCEL_FILE");
        let error = match outcome {
            Err(error) => error,
            Ok(_) => panic!("cancelled build must fail"),
        };
        assert!(matches!(error, DockerfileBuildError::Cancelled(_)));
        let journal = load_build_journal(&runtime_dir)
            .unwrap()
            .expect("cancelled build must be journaled");
        assert_eq!(journal.state, BuildJournalState::Cancelled);
        assert!(journal.completed_stages.is_empty());
        assert!(
            crate::image_tagging::resolve_reference(&store, "local/cancel:latest")
                .unwrap()
                .is_none(),
            "cancelled build must not publish an image reference"
        );
    }

    #[test]
    fn cancelled_build_does_not_replay_the_build_cache() {
        let _env = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().unwrap();
        let (dockerfile, runtime_dir, store) = write_minimal_build_fixture(temp.path());
        let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();
        build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/cache-cancel:latest"),
            &runtime_dir,
            CompressionFormat::Gzip,
            &store,
            &authority,
        )
        .expect("seed build for cache replay");
        let cancel_file = temp.path().join("cancel.flag");
        fs::write(&cancel_file, b"cancel").unwrap();
        std::env::set_var("FERROCRATE_BUILD_CANCEL_FILE", &cancel_file);
        let outcome = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/cache-cancel:latest"),
            &runtime_dir,
            CompressionFormat::Gzip,
            &store,
            &authority,
        );
        std::env::remove_var("FERROCRATE_BUILD_CANCEL_FILE");
        assert!(
            matches!(outcome, Err(DockerfileBuildError::Cancelled(_))),
            "cancel must win over an otherwise valid cache hit"
        );
        let journal = load_build_journal(&runtime_dir)
            .unwrap()
            .expect("cancelled replay must be journaled");
        assert_eq!(journal.state, BuildJournalState::Cancelled);
    }

    #[test]
    fn build_journal_records_bound_identities_on_completion() {
        let _env = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().unwrap();
        let (dockerfile, runtime_dir, store) = write_minimal_build_fixture(temp.path());
        let result = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/journal:latest"),
            &runtime_dir,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .unwrap();
        let journal = load_build_journal(&runtime_dir)
            .unwrap()
            .expect("completed build must be journaled");
        assert_eq!(journal.state, BuildJournalState::Complete);
        assert!(journal.image_reference.ends_with("local/journal:latest"));
        assert_eq!(journal.completed_stages, vec![0]);
        assert!(!journal.context_digest.is_empty());
        let dockerfile_digest = hex::encode(sha2::Sha256::digest(
            fs::read_to_string(&dockerfile).unwrap().as_bytes(),
        ));
        assert_eq!(journal.dockerfile_digest, dockerfile_digest);
        assert_eq!(journal.base_digests, vec!["scratch".to_string()]);
        assert!(journal.authorization_plan_digest.is_none());
        assert!(
            crate::image_tagging::resolve_reference(&store, &result.reference)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn identity_change_discards_stale_journal_and_checkpoints() {
        let _env = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().unwrap();
        let (dockerfile, runtime_dir, store) = write_minimal_build_fixture(temp.path());
        let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();
        let first = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/retry:latest"),
            &runtime_dir,
            CompressionFormat::Gzip,
            &store,
            &authority,
        )
        .unwrap();
        // Tamper the journaled context identity to simulate a stale journal
        // from a different source state, then force a rebuild.
        let mut stale = load_build_journal(&runtime_dir).unwrap().unwrap();
        stale.context_digest = "0".repeat(64);
        save_build_journal(&runtime_dir, &stale).unwrap();
        assert!(stage_checkpoint_path(&runtime_dir).is_file());
        fs::remove_file(build_cache_path(&runtime_dir)).unwrap();

        let second = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/retry:latest"),
            &runtime_dir,
            CompressionFormat::Gzip,
            &store,
            &authority,
        )
        .unwrap();
        let journal = load_build_journal(&runtime_dir).unwrap().unwrap();
        assert_eq!(journal.state, BuildJournalState::Complete);
        assert_ne!(journal.context_digest, "0".repeat(64));
        // The rebuilt checkpoints describe the current build, not the stale one.
        let checkpoints = load_stage_checkpoints(&runtime_dir).unwrap();
        assert_eq!(
            checkpoints.get(&0).unwrap().layer_digest,
            second.layer_digest
        );
        assert_eq!(first.layer_digest, second.layer_digest);
    }

    #[test]
    fn malformed_build_journal_fails_closed() {
        let _env = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().unwrap();
        let (dockerfile, runtime_dir, store) = write_minimal_build_fixture(temp.path());
        fs::create_dir_all(runtime_dir.join("build")).unwrap();
        fs::write(build_journal_path(&runtime_dir), b"{not json").unwrap();
        let outcome = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/malformed:latest"),
            &runtime_dir,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        );
        let error = match outcome {
            Err(error) => error,
            Ok(_) => panic!("malformed journal must fail the build"),
        };
        assert!(error.to_string().contains("journal is malformed"));
    }

    #[test]
    fn step_limit_fails_closed_before_any_stage_work() {
        let _env = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().unwrap();
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(
            &dockerfile,
            "FROM scratch\nRUN echo one\nRUN echo two\nCOPY . /\n",
        )
        .unwrap();
        fs::write(temp.path().join("hello.txt"), "steps").unwrap();
        let runtime_dir = temp.path().join("runtime");
        let store = LocalImageStore::open(runtime_dir.join("images")).unwrap();
        std::env::set_var("FERROCRATE_BUILD_MAX_STEPS", "1");
        let outcome = build_from_dockerfile_with_store_and_compression(
            &dockerfile,
            Some("local/steps:latest"),
            &runtime_dir,
            CompressionFormat::Gzip,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        );
        std::env::remove_var("FERROCRATE_BUILD_MAX_STEPS");
        let error = match outcome {
            Err(error) => error,
            Ok(_) => panic!("step limit must fail the build"),
        };
        assert!(matches!(error, DockerfileBuildError::LimitExceeded(_)));
        assert!(error.to_string().contains("RUN steps"));
        assert!(
            crate::image_tagging::resolve_reference(&store, "local/steps:latest")
                .unwrap()
                .is_none()
        );
        assert!(
            !stage_checkpoint_path(&runtime_dir).exists(),
            "no stage may execute before the step limit is enforced"
        );
    }
}
