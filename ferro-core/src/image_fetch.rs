use crate::docker_auth::resolve_registry_auth;
use crate::image_manifest::{parse_image_index, parse_image_manifest};
use crate::image_store::LocalImageStore;
use crate::image_tagging::ImageTaggingError;
use crate::registry::parse_image_reference;
use crate::registry::{RegistryAuth, RegistryClient};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
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
    let auth = resolve_registry_auth(image)?;
    inspect_image_binding_with_auth(image, auth.as_ref())
}

/// Resolve an immutable image binding with caller-supplied registry
/// credentials. Session-scoped callers use this without persisting secrets.
pub fn inspect_image_binding_with_auth(
    image: &str,
    auth: Option<&RegistryAuth>,
) -> Result<InspectedImageBinding, ImageFetchError> {
    parse_image_reference(image)?;
    let client = RegistryClient::new()?;
    let manifest_json = resolve_manifest_json(&client, image, auth)?;
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
    verify_size(&config_path, manifest.config.size)?;
    let _ = ensure_cas_blob(runtime_dir, &config_path)?;

    let layer_paths = pull_layers_concurrently(
        &client,
        &canonical,
        auth.as_ref(),
        runtime_dir,
        &manifest.layers,
    )?;

    Ok(ImageFetchResult {
        reference: canonical,
        layer_paths,
    })
}

/// Execute an already inspected plan by addressing the manifest through its
/// digest. The complete immutable binding is checked before any directory,
/// blob, or store record is written.
#[allow(dead_code)] // Directly exercises immutable-fetch fail-closed tests.
fn pull_planned_image_with_store(
    runtime_dir: &Path,
    plan: &ImageFetchPlan,
    store: &LocalImageStore,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
) -> Result<ImageFetchResult, ImageFetchError> {
    let auth = resolve_registry_auth(plan.canonical_reference())?;
    pull_planned_image_with_store_mode(runtime_dir, plan, store, true, authority, auth.as_ref())
}

fn pull_planned_image_with_store_mode(
    runtime_dir: &Path,
    plan: &ImageFetchPlan,
    store: &LocalImageStore,
    include_layers: bool,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
    auth: Option<&RegistryAuth>,
) -> Result<ImageFetchResult, ImageFetchError> {
    let client = RegistryClient::new()?;
    let fetched_json = pull_manifest_with_peer_fallback(
        &client,
        plan.immutable_reference(),
        auth,
        Some(plan.manifest_digest()),
    )?;
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
        pull_blob_with_peer_fallback(
            &client,
            plan.immutable_reference(),
            plan.config_digest(),
            auth,
            &config_path,
        )?;
    }
    verify_digest(&config_path, plan.config_digest())?;
    verify_size(&config_path, manifest.config.size)?;
    let _ = ensure_cas_blob(runtime_dir, &config_path)?;
    fs::File::open(&config_path)?.sync_all()?;

    let selected_layers: Vec<crate::image_manifest::Descriptor> = manifest
        .layers
        .iter()
        .filter(|_| include_layers)
        .cloned()
        .collect::<Vec<_>>();
    let layer_paths = pull_layers_concurrently(
        &client,
        plan.immutable_reference(),
        auth,
        runtime_dir,
        &selected_layers,
    )?;
    for layer_path in &layer_paths {
        fs::File::open(layer_path)?.sync_all()?;
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

/// Fetch independent OCI layers concurrently while preserving manifest order.
/// Each worker writes to a unique digest path and performs the same verification
/// and CAS publication as the serial path; only network latency is overlapped.
fn pull_layers_concurrently(
    client: &RegistryClient,
    reference: &str,
    auth: Option<&RegistryAuth>,
    runtime_dir: &Path,
    layers: &[crate::image_manifest::Descriptor],
) -> Result<Vec<PathBuf>, ImageFetchError> {
    if layers.is_empty() {
        return Ok(Vec::new());
    }
    let blob_root = runtime_dir.join("images").join("blobs");
    fs::create_dir_all(&blob_root)?;
    let results = std::thread::scope(|scope| {
        let workers = layers.iter().enumerate().map(|(index, layer)| {
            let digest = layer.digest.clone();
            let expected_size = layer.size;
            let blob_path = blob_root.join(digest.replace(':', "_"));
            scope.spawn(move || -> Result<(usize, PathBuf), ImageFetchError> {
                fetch_verified_layer(client, reference, auth, &digest, expected_size, &blob_path)?;
                let _ = ensure_cas_blob(runtime_dir, &blob_path)?;
                Ok((index, blob_path))
            })
        });
        workers
            .map(|worker| {
                worker.join().map_err(|_| {
                    ImageFetchError::Integrity("layer fetch worker panicked".to_string())
                })?
            })
            .collect::<Result<Vec<_>, ImageFetchError>>()
    })?;
    let mut ordered = results;
    ordered.sort_by_key(|(index, _)| *index);
    Ok(ordered
        .into_iter()
        .map(|(_, path)| path)
        .collect::<Vec<_>>())
}

pub fn pull_manifest_only_with_store_authorized(
    runtime_dir: &Path,
    plan: &ImageFetchPlan,
    store: &LocalImageStore,
    permit: crate::authorization::surface::SurfacePermit,
) -> Result<String, ImageFetchError> {
    validate_fetch_plan_permit(plan, &permit)?;
    let authority = permit.mutation_authority();
    let auth = resolve_registry_auth(plan.canonical_reference())?;
    match pull_planned_image_with_store_mode(
        runtime_dir,
        plan,
        store,
        false,
        &authority,
        auth.as_ref(),
    ) {
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
    let auth = resolve_registry_auth(plan.canonical_reference())?;
    pull_image_with_store_authorized_with_auth(runtime_dir, plan, store, permit, auth.as_ref())
}

/// Execute an authorized immutable pull with caller-supplied credentials.
/// Credentials are borrowed only for registry requests and are never stored.
pub fn pull_image_with_store_authorized_with_auth(
    runtime_dir: &Path,
    plan: &ImageFetchPlan,
    store: &LocalImageStore,
    permit: crate::authorization::surface::SurfacePermit,
    auth: Option<&RegistryAuth>,
) -> Result<ImageFetchResult, ImageFetchError> {
    if let Err(error) = validate_fetch_plan_permit(plan, &permit) {
        permit
            .finish(false)
            .map_err(|error| ImageFetchError::Integrity(error.to_string()))?;
        return Err(error);
    }
    let authority = permit.mutation_authority();
    match pull_planned_image_with_store_mode(runtime_dir, plan, store, true, &authority, auth) {
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
    verify_size(&config_path, manifest.config.size)?;
    let _ = ensure_cas_blob(runtime_dir, &config_path)?;

    Ok(canonical)
}

fn resolve_manifest_json(
    client: &RegistryClient,
    image: &str,
    auth: Option<&crate::registry::RegistryAuth>,
) -> Result<String, ImageFetchError> {
    let manifest_json = pull_manifest_with_peer_fallback(client, image, auth, None)?;
    let manifest_error = match parse_image_manifest(&manifest_json) {
        Ok(_) => return Ok(manifest_json),
        Err(error) => error,
    };

    // The document may be an image index: select the platform manifest and
    // address it through its digest. When index parsing or validation fails,
    // surface that explicit error instead of forwarding an unparseable body.
    let index = parse_image_index(&manifest_json)?;
    if let Some(digest) = select_platform_manifest(&index.manifests) {
        let parsed = parse_image_reference(image)?;
        let reference = format!("{}/{}@{}", parsed.registry, parsed.repository, digest);
        return pull_manifest_with_peer_fallback(client, &reference, auth, Some(&digest));
    }

    Err(manifest_error.into())
}

fn lan_mirror_enabled() -> bool {
    std::env::var("FERROCRATE_LAN_MIRROR")
        .is_ok_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

fn peer_get(
    image: &str,
    kind: &str,
    value: &str,
    wanted: Option<&str>,
) -> Option<(Vec<u8>, String)> {
    if !lan_mirror_enabled() {
        return None;
    }
    let reference = parse_image_reference(image).ok()?;
    let timeout_ms = std::env::var("FERROCRATE_LAN_MIRROR_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1200)
        .clamp(100, 5000);
    let report = match crate::lan_mirror::discover_report(Duration::from_millis(timeout_ms), wanted)
    {
        Ok(report) => report,
        Err(error) => {
            eprintln!("lan mirror: browse failed after {timeout_ms} ms, 0 peers: {error}");
            return None;
        }
    };
    eprintln!(
        "{}",
        crate::lan_mirror::discovery_summary(report.elapsed, report.peers.len(), report.probed)
    );
    let http = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_millis(500))
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;
    for peer in report.peers {
        let url = format!(
            "{}/v2/{}/{kind}/{value}",
            peer.base_url(),
            reference.repository
        );
        let mut request = http.get(url);
        if let Ok(secret) = std::env::var("FERROCRATE_LAN_MIRROR_SECRET") {
            let Ok(challenge) = http
                .get(format!("{}/lan/v1/challenge", peer.base_url()))
                .send()
            else {
                continue;
            };
            if !challenge.status().is_success() {
                continue;
            }
            let nonce = challenge
                .headers()
                .get("x-ferrocrate-mirror-nonce")
                .and_then(|value| value.to_str().ok());
            let proof = challenge
                .headers()
                .get("x-ferrocrate-mirror-proof")
                .and_then(|value| value.to_str().ok());
            let Some(nonce) = nonce.filter(|value| {
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            }) else {
                continue;
            };
            if !crate::lan_mirror::verify_peer_proof(&secret, nonce, proof) {
                continue;
            }
            request = request.header("X-Ferrocrate-Mirror-Nonce", nonce).header(
                "X-Ferrocrate-Mirror-Auth",
                crate::lan_mirror::mirror_request_auth(&secret, nonce, value),
            );
        }
        let Ok(response) = request.send() else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let Ok(bytes) = response.bytes() else {
            continue;
        };
        return Some((bytes.to_vec(), peer.instance_id));
    }
    None
}

fn pull_manifest_with_peer_fallback(
    client: &RegistryClient,
    image: &str,
    auth: Option<&RegistryAuth>,
    wanted_digest: Option<&str>,
) -> Result<String, ImageFetchError> {
    let reference = parse_image_reference(image)?;
    if let Some((bytes, peer)) = peer_get(image, "manifests", &reference.reference, wanted_digest) {
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        if wanted_digest.is_none_or(|wanted| wanted == digest) {
            if let Ok(manifest) = String::from_utf8(bytes) {
                eprintln!("manifest {digest}: peer {peer}");
                return Ok(manifest);
            }
        }
        eprintln!("manifest {digest}: peer mismatch, falling back to registry");
    }
    Ok(client.pull_manifest_raw(image, auth)?)
}

fn pull_blob_with_peer_fallback(
    client: &RegistryClient,
    image: &str,
    digest: &str,
    auth: Option<&RegistryAuth>,
    dest: &Path,
) -> Result<(), ImageFetchError> {
    if let Some((bytes, peer)) = peer_get(image, "blobs", digest, Some(digest)) {
        if crate::lan_mirror::verify_bytes(&bytes, digest) {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            let temporary = dest.with_extension(format!("lan-tmp-{}", uuid::Uuid::new_v4()));
            fs::write(&temporary, bytes)?;
            fs::File::open(&temporary)?.sync_all()?;
            fs::rename(&temporary, dest)?;
            eprintln!("layer {digest}: peer {peer} (verified)");
            return Ok(());
        }
        eprintln!("layer {digest}: peer mismatch, falling back to registry");
    }
    client.pull_blob_to_file(image, digest, auth, dest)?;
    eprintln!("layer {digest}: registry (verified)");
    Ok(())
}

/// Fetch a layer only after its descriptor size and digest both validate.
///
/// Registry clients can report a successful response after receiving a short
/// body (for example, when an intermediary supplies a shorter content length).
/// Never let that blob reach layer decompression: retry the whole layer download
/// from an atomic temporary file instead.
fn fetch_verified_layer(
    client: &RegistryClient,
    image: &str,
    auth: Option<&RegistryAuth>,
    digest: &str,
    expected_size: i64,
    dest: &Path,
) -> Result<(), ImageFetchError> {
    const MAX_LAYER_FETCH_ATTEMPTS: usize = 3;
    let mut last_error = None;

    for attempt in 1..=MAX_LAYER_FETCH_ATTEMPTS {
        if attempt > 1 || !dest.exists() {
            if let Err(error) = pull_blob_with_peer_fallback(client, image, digest, auth, dest) {
                eprintln!(
                    "layer {digest}: fetch attempt {attempt}/{MAX_LAYER_FETCH_ATTEMPTS} failed: {error}; retrying"
                );
                last_error = Some(error);
                continue;
            }
        }

        match verify_size(dest, expected_size).and_then(|()| verify_digest(dest, digest)) {
            Ok(()) => return Ok(()),
            Err(error) => {
                let actual_size = fs::metadata(dest).map(|metadata| metadata.len()).ok();
                let actual_size = actual_size
                    .map(|size| size.to_string())
                    .unwrap_or_else(|| "unavailable".to_string());
                eprintln!(
                    "layer {digest}: fetch attempt {attempt}/{MAX_LAYER_FETCH_ATTEMPTS} validation failed: expected {expected_size} bytes, got {actual_size} bytes: {error}; retrying"
                );
                last_error = Some(error);
            }
        }
    }

    Err(last_error.expect("layer fetch attempts always record an error"))
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
    let store = LocalImageStore::open(runtime_dir.join("images"))?;
    resolve_layer_paths_with_store(runtime_dir, image, &store)
}

pub fn resolve_layer_paths_with_store(
    runtime_dir: &Path,
    image: &str,
    store: &LocalImageStore,
) -> Result<Vec<PathBuf>, ImageFetchError> {
    let record = crate::image_tagging::resolve_reference(store, image)?
        .ok_or_else(|| crate::registry::RegistryError::InvalidReference(image.to_string()))?;
    let canonical = record.reference.clone();

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
        fetch_verified_layer(
            &client,
            &canonical,
            auth.as_ref(),
            &layer.digest,
            layer.size,
            &blob_path,
        )?;
        let _ = ensure_cas_blob(runtime_dir, &blob_path)?;
        layer_paths.push(blob_path);
    }
    Ok(layer_paths)
}

pub fn resolve_config_path(
    runtime_dir: &Path,
    image: &str,
) -> Result<Option<PathBuf>, ImageFetchError> {
    let store = LocalImageStore::open(runtime_dir.join("images"))?;
    resolve_config_path_with_store(runtime_dir, image, &store)
}

pub fn resolve_config_path_with_store(
    runtime_dir: &Path,
    image: &str,
    store: &LocalImageStore,
) -> Result<Option<PathBuf>, ImageFetchError> {
    let record = crate::image_tagging::resolve_reference(store, image)?;
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
        // Never move the published blob while another container may be
        // opening it. Copy to a create-new temporary file, sync it, then
        // atomically rename into the CAS. A racing publisher can safely lose
        // the rename and reuse the complete winner.
        let thread_id = format!("{:?}", std::thread::current().id());
        let temporary = cas_root.join(format!(
            ".{}.{}.{}.tmp",
            std::process::id(),
            std::thread::current().name().unwrap_or("writer"),
            thread_id
        ));
        let mut output = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temporary)?;
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temporary)?
            }
            Err(error) => return Err(error.into()),
        };
        let copy_result = (|| -> Result<(), ImageFetchError> {
            let mut input = fs::File::open(blob_path)?;
            std::io::copy(&mut input, &mut output)?;
            output.flush()?;
            output.sync_all()?;
            Ok(())
        })();
        drop(output);
        if let Err(error) = copy_result {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = fs::rename(&temporary, &cas_path) {
            let _ = fs::remove_file(&temporary);
            if !cas_path.exists() {
                return Err(error.into());
            }
        }
    }

    // Keep an existing published blob untouched; only materialize the link
    // when a prior migration removed it.
    if !blob_path.exists() && fs::hard_link(&cas_path, blob_path).is_err() {
        fs::copy(&cas_path, blob_path)?;
    }

    Ok(cas_path)
}

fn hash_file_shake256(path: &Path) -> Result<String, ImageFetchError> {
    let mut file = fs::File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(hex::encode(rvf_crypto::shake256_256(&buf)))
}

/// Fail closed when a fetched blob's length differs from the descriptor size
/// the manifest advertised. A matching digest with a wrong size is still an
/// inconsistent descriptor and must not be published.
fn verify_size(path: &Path, expected: i64) -> Result<(), ImageFetchError> {
    let actual = fs::metadata(path)?.len();
    if actual != expected as u64 {
        return Err(ImageFetchError::Integrity(format!(
            "descriptor size mismatch: expected {expected} bytes got {actual} for {}",
            path.display()
        )));
    }
    Ok(())
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
        ensure_cas_blob, inspect_image_binding, pull_image, pull_manifest_only,
        pull_planned_image_with_store, ImageFetchError, ImageFetchPlan,
    };
    use crate::image_store::LocalImageStore;
    use httptest::matchers::request;
    use httptest::responders::status_code;
    use httptest::{Expectation, Server};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::Arc;

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
    fn concurrent_cas_publication_keeps_blob_complete() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = temp.path().join("runtime");
        let blob = runtime.join("images/blobs/layer");
        fs::create_dir_all(blob.parent().unwrap()).expect("blob parent");
        let payload = vec![0x5a; 128 * 1024];
        fs::write(&blob, &payload).expect("blob");
        let blob = Arc::new(blob);
        let workers = (0..8)
            .map(|_| {
                let blob = Arc::clone(&blob);
                let runtime = runtime.clone();
                std::thread::spawn(move || ensure_cas_blob(&runtime, &blob).expect("cas"))
            })
            .collect::<Vec<_>>();
        let paths = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect::<Vec<_>>();
        assert!(paths.iter().all(|path| path == &paths[0]));
        assert_eq!(fs::read(&*blob).expect("published blob"), payload);
        assert_eq!(fs::read(&paths[0]).expect("cas blob"), payload);
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
    fn planned_pull_rejects_substituted_layer_blob() {
        let server = Server::run();
        let layer_payload = b"real layer bytes";
        let layer_digest = format!("sha256:{:x}", Sha256::digest(layer_payload));
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be","size":13}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer_digest}","size":{}}}]}}"#,
            layer_payload.len()
        );
        let image = format!("{}/library/layer-swap:latest", server.addr());
        let plan = ImageFetchPlan::from_resolved_manifest(&image, &manifest).unwrap();
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!(
                    "/v2/library/layer-swap/manifests/{}",
                    plan.manifest_digest()
                ),
            ))
            .respond_with(status_code(200).body(manifest)),
        );
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                "/v2/library/layer-swap/blobs/sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be",
            ))
            .respond_with(status_code(200).body("{\"config\":{}}")),
        );
        // The registry serves different bytes than the descriptor digest
        // promises: a substituted blob must fail verification and prevent
        // any store publication.
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!("/v2/library/layer-swap/blobs/{layer_digest}"),
            ))
            // fetch_verified_layer retries the download after a validation
            // failure, so the mock must accept repeated requests.
            .times(1..)
            .respond_with(status_code(200).body("substituted payload")),
        );
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path().join("images")).unwrap();

        let error = pull_planned_image_with_store(
            temp.path(),
            &plan,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect_err("substituted layer blob must fail closed");

        assert!(
            error.to_string().contains("digest verification failed"),
            "expected digest verification failure, got {error}"
        );
        assert!(store.list_references().unwrap().is_empty());
    }

    #[test]
    fn pulls_manifest_and_layers() {
        let server = Server::run();
        let manifest_json = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be","size":13},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:94ee059335e587e501cc4bf90613e0814f00a7b08bc7c648fd865a2af6a22cc2","size":4}]}"#;

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
    fn retries_a_truncated_gzip_layer_before_rootfs_decompression() {
        let plain_layer = {
            let mut builder = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_gnu();
            header.set_path("usr/bin/ready").unwrap();
            header.set_size(2);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append(&header, b"ok".as_slice()).unwrap();
            builder.into_inner().unwrap()
        };
        let gzip_layer = crate::layer_compression::compress_bytes_gzip(&plain_layer).unwrap();
        let config = b"{\"config\":{}}";
        let config_digest = format!("sha256:{:x}", Sha256::digest(config));
        let layer_digest = format!("sha256:{:x}", Sha256::digest(&gzip_layer));
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer_digest}","size":{}}}]}}"#,
            config.len(),
            gzip_layer.len(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_layer = gzip_layer.clone();
        let server = std::thread::spawn(move || {
            for response in [
                manifest.into_bytes(),
                config.to_vec(),
                server_layer[..server_layer.len() - 8].to_vec(),
                server_layer,
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .unwrap();
                stream.write_all(&response).unwrap();
            }
        });
        let temp = tempfile::tempdir().unwrap();
        let image = format!("{address}/library/truncated:latest");

        let result = pull_image(
            temp.path(),
            &image,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect("a short layer must be retried before it reaches gzip decompression");
        server.join().unwrap();

        let rootfs = temp.path().join("rootfs");
        crate::rootfs::construct_rootfs(&rootfs, &result.layer_paths)
            .expect("retried gzip layer must decompress");
        assert_eq!(fs::read(rootfs.join("usr/bin/ready")).unwrap(), b"ok");
    }

    #[test]
    fn inspects_immutable_binding_without_mutating_the_store() {
        let server = Server::run();
        let manifest_json = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be","size":13},"layers":[]}"#;
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
    fn planned_pull_rejects_config_size_mismatch() {
        let server = Server::run();
        let config_bytes = b"{\"config\":{}}";
        let config_digest = format!("sha256:{:x}", Sha256::digest(config_bytes));
        // The descriptor advertises a size that does not match the blob the
        // registry serves. The digest is correct, so only an explicit size
        // check can catch this inconsistency.
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},"layers":[]}}"#,
            config_bytes.len() + 1
        );
        let image = format!("{}/library/size-mismatch:latest", server.addr());
        let plan = ImageFetchPlan::from_resolved_manifest(&image, &manifest).unwrap();
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!(
                    "/v2/library/size-mismatch/manifests/{}",
                    plan.manifest_digest()
                ),
            ))
            .respond_with(status_code(200).body(manifest)),
        );
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!("/v2/library/size-mismatch/blobs/{config_digest}"),
            ))
            .respond_with(status_code(200).body(config_bytes.to_vec())),
        );
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path().join("images")).unwrap();

        let error = pull_planned_image_with_store(
            temp.path(),
            &plan,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect_err("config size mismatch must fail closed");

        assert!(
            error.to_string().contains("size mismatch"),
            "expected size mismatch failure, got {error}"
        );
        assert!(store.list_references().unwrap().is_empty());
    }

    #[test]
    fn planned_pull_rejects_layer_size_mismatch() {
        let server = Server::run();
        let config_bytes = b"{\"config\":{}}";
        let config_digest = format!("sha256:{:x}", Sha256::digest(config_bytes));
        let layer_bytes = b"layer payload";
        let layer_digest = format!("sha256:{:x}", Sha256::digest(layer_bytes));
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer_digest}","size":{}}}]}}"#,
            config_bytes.len(),
            layer_bytes.len() - 1
        );
        let image = format!("{}/library/layer-size:latest", server.addr());
        let plan = ImageFetchPlan::from_resolved_manifest(&image, &manifest).unwrap();
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!(
                    "/v2/library/layer-size/manifests/{}",
                    plan.manifest_digest()
                ),
            ))
            .respond_with(status_code(200).body(manifest)),
        );
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!("/v2/library/layer-size/blobs/{config_digest}"),
            ))
            .respond_with(status_code(200).body(config_bytes.to_vec())),
        );
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!("/v2/library/layer-size/blobs/{layer_digest}"),
            ))
            // fetch_verified_layer retries the download after a validation
            // failure, so the mock must accept repeated requests.
            .times(1..)
            .respond_with(status_code(200).body(layer_bytes.to_vec())),
        );
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path().join("images")).unwrap();

        let error = pull_planned_image_with_store(
            temp.path(),
            &plan,
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
        )
        .expect_err("layer size mismatch must fail closed");

        assert!(
            error.to_string().contains("size mismatch"),
            "expected size mismatch failure, got {error}"
        );
        assert!(store.list_references().unwrap().is_empty());
    }

    #[test]
    fn fetch_plan_rejects_unknown_digest_algorithm() {
        let manifest = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}"#;
        let error =
            ImageFetchPlan::from_resolved_manifest("example.test/library/alpine:latest", manifest)
                .expect_err("unknown digest algorithm must fail closed");
        assert!(
            error.to_string().contains("invalid descriptor digest"),
            "expected explicit digest rejection, got {error}"
        );
    }

    #[test]
    fn pulls_manifest_only_without_layers() {
        let server = Server::run();
        let manifest_json = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be","size":13},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","size":4}]}"#;

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

    #[test]
    fn cross_repository_digest_lookup_fetches_missing_blobs_from_requested_repository() {
        let source = Server::run();
        let requested = Server::run();
        let layer = b"repository-bound-layer";
        let layer_digest = format!("sha256:{:x}", Sha256::digest(layer));
        let config_digest = format!("sha256:{}", "a".repeat(64));
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":1}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer_digest}","size":{}}}]}}"#,
            layer.len()
        );
        requested.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!("/v2/team/app/blobs/{layer_digest}"),
            ))
            .respond_with(status_code(200).body(layer.to_vec())),
        );
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path().join("images")).unwrap();
        store
            .put_reference(
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                &format!("{}/team/app:latest", source.addr()),
                &config_digest,
                "application/vnd.oci.image.manifest.v1+json",
                &manifest,
            )
            .unwrap();
        let selector = format!("{}/team/app@{config_digest}", requested.addr());
        let paths = super::resolve_layer_paths_with_store(temp.path(), &selector, &store)
            .expect("missing blob is fetched through the requested repository");
        assert_eq!(std::fs::read(&paths[0]).unwrap(), layer);
    }
}
