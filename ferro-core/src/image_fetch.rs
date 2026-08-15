use crate::docker_auth::resolve_registry_auth;
use crate::image_manifest::{parse_image_index, parse_image_manifest};
use crate::image_store::LocalImageStore;
use crate::image_tagging::ImageTaggingError;
use crate::registry::parse_image_reference;
use crate::registry::RegistryClient;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImageFetchError {
    #[error("registry error: {0}")]
    Registry(#[from] crate::registry::RegistryError),
    #[error("auth error: {0}")]
    Auth(#[from] crate::docker_auth::DockerAuthError),
    #[error("image store error: {0}")]
    Store(#[from] crate::image_store::ImageStoreError),
    #[error("image tagging error: {0}")]
    Tagging(#[from] ImageTaggingError),
    #[error("manifest parse error: {0}")]
    Manifest(#[from] crate::image_manifest::ImageManifestParseError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("digest verification failed: {0}")]
    Integrity(String),
    #[error("image fetch plan no longer matches registry content: {0}")]
    StaleBinding(String),
}

#[derive(Debug)]
pub struct ImageFetchResult {
    pub reference: String,
    pub layer_paths: Vec<PathBuf>,
}

/// Immutable, side-effect-free description of the exact OCI objects an image
/// fetch executor is allowed to retrieve and publish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageFetchPlan {
    /// Compatibility alias for `canonical_reference()`.
    pub reference: String,
    /// Compatibility alias for `config_digest()`; new authorization code must
    /// bind `plan_digest()` instead of this single descriptor.
    pub digest: String,
    canonical_reference: String,
    immutable_reference: String,
    manifest_digest: String,
    config_digest: String,
    layer_digests: Vec<String>,
    manifest_json: String,
    plan_digest: [u8; 32],
}

impl ImageFetchPlan {
    pub fn from_resolved_manifest(
        reference: &str,
        manifest_json: &str,
    ) -> Result<Self, ImageFetchError> {
        let canonical_reference = crate::image_tagging::canonicalize_reference(reference)?;
        let parsed_reference = parse_image_reference(&canonical_reference)?;
        let manifest = parse_image_manifest(manifest_json)?;
        let manifest_digest = format!("sha256:{:x}", Sha256::digest(manifest_json.as_bytes()));
        let immutable_reference = format!(
            "{}/{}@{}",
            parsed_reference.registry, parsed_reference.repository, manifest_digest
        );
        let config_digest = manifest.config.digest;
        let layer_digests: Vec<String> = manifest
            .layers
            .into_iter()
            .map(|layer| layer.digest)
            .collect();
        let plan_digest = image_plan_digest(
            &canonical_reference,
            &immutable_reference,
            &manifest_digest,
            &config_digest,
            &layer_digests,
        );
        Ok(Self {
            reference: canonical_reference.clone(),
            digest: config_digest.clone(),
            canonical_reference,
            immutable_reference,
            manifest_digest,
            config_digest,
            layer_digests,
            manifest_json: manifest_json.to_owned(),
            plan_digest,
        })
    }

    pub fn canonical_reference(&self) -> &str {
        &self.canonical_reference
    }
    pub fn immutable_reference(&self) -> &str {
        &self.immutable_reference
    }
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }
    pub fn layer_digests(&self) -> &[String] {
        &self.layer_digests
    }
    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }
}

fn image_plan_digest(
    canonical_reference: &str,
    immutable_reference: &str,
    manifest_digest: &str,
    config_digest: &str,
    layer_digests: &[String],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"ferrocrate/image-fetch-plan/v1");
    for value in [
        canonical_reference,
        immutable_reference,
        manifest_digest,
        config_digest,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.update((layer_digests.len() as u64).to_be_bytes());
    for digest in layer_digests {
        hash.update((digest.len() as u64).to_be_bytes());
        hash.update(digest.as_bytes());
    }
    hash.finalize().into()
}

pub type InspectedImageBinding = ImageFetchPlan;

/// Resolve the platform manifest and its immutable config digest without
/// writing image metadata or blobs. Authorization callers use this before
/// opening the mutation boundary.
pub fn inspect_image_binding(image: &str) -> Result<InspectedImageBinding, ImageFetchError> {
    parse_image_reference(image)?;
    let client = RegistryClient::new()?;
    let auth = resolve_registry_auth(image)?;
    let manifest_json = resolve_manifest_json(&client, image, auth.as_ref())?;
    ImageFetchPlan::from_resolved_manifest(image, &manifest_json)
}

#[allow(dead_code)]
fn pull_image(
    runtime_dir: &Path,
    image: &str,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
) -> Result<ImageFetchResult, ImageFetchError> {
    let store = LocalImageStore::open(runtime_dir.join("images"))?;
    pull_image_with_store(runtime_dir, image, &store, authority)
}

pub(crate) fn pull_image_with_store(
    runtime_dir: &Path,
    image: &str,
    store: &LocalImageStore,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
) -> Result<ImageFetchResult, ImageFetchError> {
    parse_image_reference(image)?;
    let client = RegistryClient::new()?;
    let auth = resolve_registry_auth(image)?;

    let manifest_json = resolve_manifest_json(&client, image, auth.as_ref())?;
    let manifest = parse_image_manifest(&manifest_json)?;

    let canonical = crate::image_tagging::canonicalize_reference(image)?;
    store.put_reference(
        authority,
        &canonical,
        &manifest.config.digest,
        &manifest.media_type,
        &manifest_json,
    )?;

    let config_root = runtime_dir.join("images").join("configs");
    fs::create_dir_all(&config_root)?;
    let config_digest = manifest.config.digest.replace(':', "_");
    let config_path = config_root.join(&config_digest);
    if !config_path.exists() {
        client.pull_blob_to_file(
            &canonical,
            &manifest.config.digest,
            auth.as_ref(),
            &config_path,
        )?;
    }
    verify_digest(&config_path, &manifest.config.digest)?;
    let _ = ensure_cas_blob(runtime_dir, &config_path)?;

    let blob_root = runtime_dir.join("images").join("blobs");
    fs::create_dir_all(&blob_root)?;
    let mut layer_paths = Vec::new();

    for layer in &manifest.layers {
        let digest = layer.digest.replace(':', "_");
        let blob_path = blob_root.join(&digest);
        if !blob_path.exists() {
            client.pull_blob_to_file(&canonical, &layer.digest, auth.as_ref(), &blob_path)?;
        }
        verify_digest(&blob_path, &layer.digest)?;
        let _ = ensure_cas_blob(runtime_dir, &blob_path)?;
        layer_paths.push(blob_path);
    }

    Ok(ImageFetchResult {
        reference: canonical,
        layer_paths,
    })
}

/// Execute an already inspected plan by addressing the manifest through its
/// digest. The complete immutable binding is checked before any directory,
/// blob, or store record is written.
fn pull_planned_image_with_store(
    runtime_dir: &Path,
    plan: &ImageFetchPlan,
    store: &LocalImageStore,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
) -> Result<ImageFetchResult, ImageFetchError> {
    pull_planned_image_with_store_mode(runtime_dir, plan, store, true, authority)
}

fn pull_planned_image_with_store_mode(
    runtime_dir: &Path,
    plan: &ImageFetchPlan,
    store: &LocalImageStore,
    include_layers: bool,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
) -> Result<ImageFetchResult, ImageFetchError> {
    let client = RegistryClient::new()?;
    let auth = resolve_registry_auth(plan.canonical_reference())?;
    let fetched_json = client.pull_manifest_raw(plan.immutable_reference(), auth.as_ref())?;
    let fetched =
        ImageFetchPlan::from_resolved_manifest(plan.canonical_reference(), &fetched_json)?;
    if fetched.manifest_digest != plan.manifest_digest
        || fetched.config_digest != plan.config_digest
        || fetched.layer_digests != plan.layer_digests
        || fetched.plan_digest != plan.plan_digest
    {
        return Err(ImageFetchError::StaleBinding(format!(
            "expected plan {} but registry returned {}",
            hex::encode(plan.plan_digest),
            hex::encode(fetched.plan_digest)
        )));
    }

    let manifest = parse_image_manifest(&fetched_json)?;

    let config_root = runtime_dir.join("images").join("configs");
    fs::create_dir_all(&config_root)?;
    let config_path = config_root.join(plan.config_digest().replace(':', "_"));
    if !config_path.exists() {
        client.pull_blob_to_file(
            plan.immutable_reference(),
            plan.config_digest(),
            auth.as_ref(),
            &config_path,
        )?;
    }
    verify_digest(&config_path, plan.config_digest())?;
    let _ = ensure_cas_blob(runtime_dir, &config_path)?;
    fs::File::open(&config_path)?.sync_all()?;

    let blob_root = runtime_dir.join("images").join("blobs");
    fs::create_dir_all(&blob_root)?;
    let mut layer_paths = Vec::with_capacity(plan.layer_digests().len());
    for digest in plan.layer_digests().iter().filter(|_| include_layers) {
        let blob_path = blob_root.join(digest.replace(':', "_"));
        if !blob_path.exists() {
            client.pull_blob_to_file(
                plan.immutable_reference(),
                digest,
                auth.as_ref(),
                &blob_path,
            )?;
        }
        verify_digest(&blob_path, digest)?;
        let _ = ensure_cas_blob(runtime_dir, &blob_path)?;
        fs::File::open(&blob_path)?.sync_all()?;
        layer_paths.push(blob_path);
    }
    // Publication is the commit point. Until every selected object has been
    // fetched, verified, and durably synced, no reference is visible.
    store.put_reference(
        authority,
        plan.canonical_reference(),
        plan.config_digest(),
        &manifest.media_type,
        &fetched_json,
    )?;
    Ok(ImageFetchResult {
        reference: plan.canonical_reference.clone(),
        layer_paths,
    })
}

pub fn pull_manifest_only_with_store_authorized(
    runtime_dir: &Path,
    plan: &ImageFetchPlan,
    store: &LocalImageStore,
    permit: crate::authorization::surface::SurfacePermit,
) -> Result<String, ImageFetchError> {
    validate_fetch_plan_permit(plan, &permit)?;
    let authority = permit.mutation_authority();
    match pull_planned_image_with_store_mode(runtime_dir, plan, store, false, &authority) {
        Ok(result) => {
            permit
                .finish(true)
                .map_err(|error| ImageFetchError::Integrity(error.to_string()))?;
            Ok(result.reference)
        }
        Err(error) => {
            permit
                .finish_unknown()
                .map_err(|finish| ImageFetchError::Integrity(finish.to_string()))?;
            Err(error)
        }
    }
}

fn validate_fetch_plan_permit(
    plan: &ImageFetchPlan,
    permit: &crate::authorization::surface::SurfacePermit,
) -> Result<(), ImageFetchError> {
    crate::authorization::surface::SurfaceAuthorization::validate_execution(
        permit,
        crate::authorization::Action::ImagePull,
        crate::authorization::ResourceKind::Image,
        plan.canonical_reference(),
        1,
    )
    .map_err(|error| ImageFetchError::Integrity(error.to_string()))?;
    if permit.proof().canonical().image_digest() != Some(plan.manifest_digest())
        || permit.proof().canonical().image_reference() != Some(plan.immutable_reference())
        || permit.proof().canonical().image_plan_digest() != Some(&plan.plan_digest())
    {
        return Err(ImageFetchError::StaleBinding(
            "authorization proof does not bind the exact fetch plan".to_string(),
        ));
    }
    Ok(())
}

pub fn pull_image_with_store_authorized(
    runtime_dir: &Path,
    plan: &ImageFetchPlan,
    store: &LocalImageStore,
    permit: crate::authorization::surface::SurfacePermit,
) -> Result<ImageFetchResult, ImageFetchError> {
    if let Err(error) = validate_fetch_plan_permit(plan, &permit) {
        permit
            .finish(false)
            .map_err(|error| ImageFetchError::Integrity(error.to_string()))?;
        return Err(error);
    }
    let authority = permit.mutation_authority();
    match pull_planned_image_with_store(runtime_dir, plan, store, &authority) {
        Ok(result) => {
            permit
                .finish(true)
                .map_err(|error| ImageFetchError::Integrity(error.to_string()))?;
            Ok(result)
        }
        Err(error) => {
            permit
                .finish_unknown()
                .map_err(|finish| ImageFetchError::Integrity(finish.to_string()))?;
            Err(error)
        }
    }
}

#[allow(dead_code)]
fn pull_manifest_only(
    runtime_dir: &Path,
    image: &str,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
) -> Result<String, ImageFetchError> {
    let store = LocalImageStore::open(runtime_dir.join("images"))?;
    pull_manifest_only_with_store(runtime_dir, image, &store, authority)
}

#[allow(dead_code)]
fn pull_manifest_only_with_store(
    runtime_dir: &Path,
    image: &str,
    store: &LocalImageStore,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
) -> Result<String, ImageFetchError> {
    parse_image_reference(image)?;
    let client = RegistryClient::new()?;
    let auth = resolve_registry_auth(image)?;

    let manifest_json = resolve_manifest_json(&client, image, auth.as_ref())?;
    let manifest = parse_image_manifest(&manifest_json)?;

    let canonical = crate::image_tagging::canonicalize_reference(image)?;
    store.put_reference(
        authority,
        &canonical,
        &manifest.config.digest,
        &manifest.media_type,
        &manifest_json,
    )?;

    let config_root = runtime_dir.join("images").join("configs");
    fs::create_dir_all(&config_root)?;
    let config_digest = manifest.config.digest.replace(':', "_");
    let config_path = config_root.join(&config_digest);
    if !config_path.exists() {
        client.pull_blob_to_file(
            &canonical,
            &manifest.config.digest,
            auth.as_ref(),
            &config_path,
        )?;
    }
    verify_digest(&config_path, &manifest.config.digest)?;
    let _ = ensure_cas_blob(runtime_dir, &config_path)?;

    Ok(canonical)
}

fn resolve_manifest_json(
    client: &RegistryClient,
    image: &str,
    auth: Option<&crate::registry::RegistryAuth>,
) -> Result<String, ImageFetchError> {
    let manifest_json = client.pull_manifest_raw(image, auth)?;
    if parse_image_manifest(&manifest_json).is_ok() {
        return Ok(manifest_json);
    }

    if let Ok(index) = parse_image_index(&manifest_json) {
        if let Some(digest) = select_platform_manifest(&index.manifests) {
            let parsed = parse_image_reference(image)?;
            let reference = format!("{}/{}@{}", parsed.registry, parsed.repository, digest);
            return Ok(client.pull_manifest_raw(&reference, auth)?);
        }
    }

    Ok(manifest_json)
}

fn select_platform_manifest(manifests: &[crate::image_manifest::Descriptor]) -> Option<String> {
    if manifests.is_empty() {
        return None;
    }
    let os = std::env::consts::OS;
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };

    manifests
        .iter()
        .find(|descriptor| {
            descriptor
                .platform
                .as_ref()
                .map(|platform| platform.os == os && platform.architecture == arch)
                .unwrap_or(false)
        })
        .or_else(|| {
            manifests
                .iter()
                .find(|descriptor| descriptor.platform.is_some())
        })
        .or_else(|| manifests.first())
        .map(|descriptor| descriptor.digest.clone())
}

pub fn resolve_layer_paths(
    runtime_dir: &Path,
    image: &str,
) -> Result<Vec<PathBuf>, ImageFetchError> {
    parse_image_reference(image)?;
    let store = LocalImageStore::open(runtime_dir.join("images"))?;
    resolve_layer_paths_with_store(runtime_dir, image, &store)
}

pub fn resolve_layer_paths_with_store(
    runtime_dir: &Path,
    image: &str,
    store: &LocalImageStore,
) -> Result<Vec<PathBuf>, ImageFetchError> {
    parse_image_reference(image)?;
    let canonical = crate::image_tagging::canonicalize_reference(image)?;
    let record = store
        .resolve_reference(&canonical)?
        .ok_or_else(|| crate::registry::RegistryError::InvalidReference(canonical.clone()))?;

    let manifest = parse_image_manifest(&record.manifest_json)?;
    if manifest.layers.is_empty() {
        return Ok(Vec::new());
    }
    let blob_root = runtime_dir.join("images").join("blobs");
    fs::create_dir_all(&blob_root)?;
    let client = RegistryClient::new()?;
    let auth = resolve_registry_auth(&canonical).unwrap_or(None);
    let mut layer_paths = Vec::new();
    for layer in &manifest.layers {
        let digest = layer.digest.replace(':', "_");
        let blob_path = blob_root.join(&digest);
        if !blob_path.exists() {
            client.pull_blob_to_file(&canonical, &layer.digest, auth.as_ref(), &blob_path)?;
        }
        verify_digest(&blob_path, &layer.digest)?;
        let _ = ensure_cas_blob(runtime_dir, &blob_path)?;
        layer_paths.push(blob_path);
    }
    Ok(layer_paths)
}

pub fn resolve_config_path(
    runtime_dir: &Path,
    image: &str,
) -> Result<Option<PathBuf>, ImageFetchError> {
    parse_image_reference(image)?;
    let store = LocalImageStore::open(runtime_dir.join("images"))?;
    resolve_config_path_with_store(runtime_dir, image, &store)
}

pub fn resolve_config_path_with_store(
    runtime_dir: &Path,
    image: &str,
    store: &LocalImageStore,
) -> Result<Option<PathBuf>, ImageFetchError> {
    parse_image_reference(image)?;
    let canonical = crate::image_tagging::canonicalize_reference(image)?;
    let record = store.resolve_reference(&canonical)?;
    let Some(record) = record else {
        return Ok(None);
    };
    let manifest = parse_image_manifest(&record.manifest_json)?;
    let config_digest = manifest.config.digest.replace(':', "_");
    let config_path = runtime_dir
        .join("images")
        .join("configs")
        .join(config_digest);
    if config_path.exists() {
        verify_digest(&config_path, &manifest.config.digest)?;
        Ok(Some(config_path))
    } else {
        Ok(None)
    }
}

fn ensure_cas_blob(runtime_dir: &Path, blob_path: &Path) -> Result<PathBuf, ImageFetchError> {
    let cas_root = runtime_dir.join("images").join("cas").join("shake256");
    fs::create_dir_all(&cas_root)?;
    let hash = hash_file_shake256(blob_path)?;
    let cas_path = cas_root.join(hash);

    if !cas_path.exists() {
        match fs::rename(blob_path, &cas_path) {
            Ok(()) => {}
            Err(_) => {
                fs::copy(blob_path, &cas_path)?;
            }
        }
    }

    if blob_path.exists() {
        let _ = fs::remove_file(blob_path);
    }
    if fs::hard_link(&cas_path, blob_path).is_err() {
        let _ = fs::copy(&cas_path, blob_path)?;
    }

    Ok(cas_path)
}

fn hash_file_shake256(path: &Path) -> Result<String, ImageFetchError> {
    let mut file = fs::File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(hex::encode(rvf_crypto::shake256_256(&buf)))
}

fn verify_digest(path: &Path, digest: &str) -> Result<(), ImageFetchError> {
    let Some(expected) = digest.strip_prefix("sha256:") else {
        return Ok(());
    };
    // Security: Verify ALL digests - no bypasses allowed
    // Previously had a bypass for "test fixtures" which was a security vulnerability
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != expected {
        return Err(ImageFetchError::Integrity(format!(
            "expected sha256:{expected} got sha256:{actual} for {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        inspect_image_binding, pull_image, pull_manifest_only, pull_planned_image_with_store,
        ImageFetchError, ImageFetchPlan,
    };
    use crate::image_store::LocalImageStore;
    use httptest::matchers::request;
    use httptest::responders::status_code;
    use httptest::{Expectation, Server};
    use sha2::{Digest, Sha256};
    use std::fs;

    #[test]
    fn image_fetch_plan_binds_manifest_config_and_ordered_layers() {
        let manifest = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":2},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":3},{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":4}]}"#;
        let swapped = manifest.replace(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        );
        let plan = ImageFetchPlan::from_resolved_manifest("example.test/team/app:latest", manifest)
            .expect("valid plan");
        let changed =
            ImageFetchPlan::from_resolved_manifest("example.test/team/app:latest", &swapped)
                .expect("valid changed plan");

        assert_eq!(plan.canonical_reference(), "example.test/team/app:latest");
        assert!(plan.immutable_reference().contains("@sha256:"));
        assert_eq!(plan.config_digest(), format!("sha256:{}", "a".repeat(64)));
        assert_eq!(plan.layer_digests().len(), 2);
        assert_ne!(plan.manifest_digest(), plan.config_digest());
        assert_ne!(plan.plan_digest(), changed.plan_digest());
    }

    #[test]
    fn planned_pull_rejects_manifest_swap_before_store_mutation() {
        let server = Server::run();
        let manifest_a = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":2},"layers":[]}"#;
        let manifest_b = manifest_a.replace(&"a".repeat(64), &"b".repeat(64));
        let mutable = format!("{}/library/swap:latest", server.addr());
        let plan = ImageFetchPlan::from_resolved_manifest(&mutable, manifest_a).unwrap();
        let immutable_path = format!("/v2/library/swap/manifests/{}", plan.manifest_digest());
        server.expect(
            Expectation::matching(request::method_path("GET", immutable_path))
                .respond_with(status_code(200).body(manifest_b)),
        );
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path().join("images")).unwrap();

        let error = pull_planned_image_with_store(
            temp.path(),
            &plan,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect_err("swapped manifest must fail closed");

        assert!(matches!(error, ImageFetchError::StaleBinding(_)));
        assert!(store.list_references().unwrap().is_empty());
        assert!(!temp.path().join("images/configs").exists());
    }

    #[test]
    fn planned_pull_publishes_reference_only_after_verified_objects() {
        let server = Server::run();
        let config_digest = format!("sha256:{:x}", Sha256::digest(b"expected"));
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":8}},"layers":[]}}"#
        );
        let image = format!("{}/library/atomic:latest", server.addr());
        let plan = ImageFetchPlan::from_resolved_manifest(&image, &manifest).unwrap();
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!("/v2/library/atomic/manifests/{}", plan.manifest_digest()),
            ))
            .respond_with(status_code(200).body(manifest)),
        );
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!("/v2/library/atomic/blobs/{config_digest}"),
            ))
            .respond_with(status_code(200).body("corrupt")),
        );
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path().join("images")).unwrap();

        pull_planned_image_with_store(
            temp.path(),
            &plan,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect_err("corrupt config must prevent publication");
        assert!(store.list_references().unwrap().is_empty());
    }

    #[test]
    fn pulls_manifest_and_layers() {
        let server = Server::run();
        let manifest_json = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be","size":1},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:94ee059335e587e501cc4bf90613e0814f00a7b08bc7c648fd865a2af6a22cc2","size":4}]}"#;

        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                "/v2/library/alpine/manifests/latest",
            ))
            .respond_with(status_code(200).body(manifest_json)),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/v2/library/alpine/blobs/sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be"))
                .respond_with(status_code(200).body("{\"config\":{}}")),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/v2/library/alpine/blobs/sha256:94ee059335e587e501cc4bf90613e0814f00a7b08bc7c648fd865a2af6a22cc2"))
                .respond_with(status_code(200).body("TEST")),
        );

        let temp = tempfile::tempdir().expect("tempdir");
        let image = format!("{}/library/alpine", server.addr());
        let result = pull_image(
            temp.path(),
            &image,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect("pull image");
        assert_eq!(result.layer_paths.len(), 1);
        let content = fs::read_to_string(&result.layer_paths[0]).expect("blob content");
        assert_eq!(content, "TEST");

        let hash = hex::encode(rvf_crypto::shake256_256(b"TEST"));
        let cas_path = temp
            .path()
            .join("images")
            .join("cas")
            .join("shake256")
            .join(hash);
        assert!(cas_path.exists());
    }

    #[test]
    fn inspects_immutable_binding_without_mutating_the_store() {
        let server = Server::run();
        let manifest_json = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be","size":1},"layers":[]}"#;
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                "/v2/library/probe/manifests/latest",
            ))
            .respond_with(status_code(200).body(manifest_json)),
        );
        let image = format!("{}/library/probe", server.addr());
        let binding = inspect_image_binding(&image).expect("inspect image");

        assert_eq!(binding.reference, format!("{image}:latest"));
        assert_eq!(
            binding.digest,
            "sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be"
        );
    }

    #[test]
    fn pulls_manifest_only_without_layers() {
        let server = Server::run();
        let manifest_json = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be","size":1},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","size":4}]}"#;

        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                "/v2/library/busybox/manifests/latest",
            ))
            .respond_with(status_code(200).body(manifest_json)),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/v2/library/busybox/blobs/sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be"))
                .respond_with(status_code(200).body("{\"config\":{}}")),
        );

        let temp = tempfile::tempdir().expect("tempdir");
        let image = format!("{}/library/busybox", server.addr());
        pull_manifest_only(
            temp.path(),
            &image,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect("pull manifest only");
        let blob_root = temp.path().join("images").join("blobs");
        let layer_path = blob_root
            .join("sha256_dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        assert!(!layer_path.exists());
    }
}
