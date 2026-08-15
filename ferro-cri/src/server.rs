use crate::runtime::image_service_server::{ImageService, ImageServiceServer};
use crate::runtime::runtime_service_server::{RuntimeService, RuntimeServiceServer};
use crate::runtime::{
    FilesystemUsage, Image, ImageFsInfoRequest, ImageFsInfoResponse, ImageStatusRequest,
    ImageStatusResponse, ListImagesRequest, ListImagesResponse, PullImageRequest,
    PullImageResponse, RemoveImageRequest, RemoveImageResponse, RuntimeCondition, RuntimeStatus,
    StatusRequest, StatusResponse, VersionRequest, VersionResponse,
};
pub use ferro_core::authorization::cri_delegation::{
    CriDelegationClaims, CriDelegationVerifier, DelegationAssertion, DelegationError,
    DelegationTrustKey,
};
use ferro_core::authorization::surface::SurfaceAuthorization;
use ferro_core::authorization::{Action, PrincipalResolver, RequestOrigin, TransportPrincipal};
use ferro_core::image_store::{ImageStoreError, LocalImageStore};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixListener;
use tokio_stream::{wrappers::UnixListenerStream, StreamExt};
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub struct CriIdentityPolicy {
    verifier: Option<Arc<CriDelegationVerifier>>,
}
impl CriIdentityPolicy {
    pub fn transport_only(_id: impl Into<String>) -> Self {
        Self { verifier: None }
    }
    pub fn with_signed_verifier(
        _id: impl Into<String>,
        verifier: Arc<CriDelegationVerifier>,
    ) -> Self {
        Self {
            verifier: Some(verifier),
        }
    }
    #[allow(clippy::result_large_err)]
    pub fn resolve(
        &self,
        transport: &TransportPrincipal,
        delegated: Option<DelegationAssertion>,
        telemetry_subject: Option<String>,
        action: Action,
        resource: &str,
        now_unix_ms: u64,
    ) -> Result<EffectiveCriIdentity, Status> {
        let accepted = match (delegated.as_ref(), self.verifier.as_ref()) {
            (Some(assertion), Some(verifier)) => Some(
                verifier
                    .verify(
                        assertion,
                        transport.principal().id().as_str(),
                        action,
                        resource,
                        now_unix_ms,
                    )
                    .map_err(|error| Status::permission_denied(error.to_string()))?,
            ),
            (Some(_), None) => {
                return Err(Status::permission_denied(
                    "signed CRI delegation is not configured",
                ))
            }
            (None, _) => None,
        };
        let origin = accepted.map_or_else(
            || RequestOrigin::cri_transport(transport),
            |verified| RequestOrigin::verified_cri_delegation(transport, verified),
        );
        let delegated_id = delegated
            .as_ref()
            .map(|value| value.claims().delegated_principal().to_owned())
            .or(telemetry_subject);
        Ok(EffectiveCriIdentity {
            transport: transport.principal().id().as_str().to_owned(),
            delegated: delegated_id,
            effective: origin.principal().id().as_str().to_owned(),
            used_delegation: origin.principal().id() != transport.principal().id(),
            origin,
        })
    }
}

#[derive(Clone, Debug)]
pub struct EffectiveCriIdentity {
    transport: String,
    delegated: Option<String>,
    effective: String,
    used_delegation: bool,
    origin: RequestOrigin,
}
impl EffectiveCriIdentity {
    pub fn transport_id(&self) -> &str {
        &self.transport
    }
    pub fn delegated_id(&self) -> Option<&str> {
        self.delegated.as_deref()
    }
    pub fn effective_id(&self) -> &str {
        &self.effective
    }
    pub fn used_delegation(&self) -> bool {
        self.used_delegation
    }
    pub fn request_origin(&self) -> &RequestOrigin {
        &self.origin
    }
}

#[allow(clippy::result_large_err)]
fn resolve_request_identity<T>(
    policy: &CriIdentityPolicy,
    request: &Request<T>,
    action: Action,
    resource: &str,
) -> Result<EffectiveCriIdentity, Status> {
    let transport = trusted_transport(request)?;
    // CRI metadata is telemetry only. A signed assertion can only arrive as
    // a typed extension inserted by a trusted transport integrity layer.
    let extension_assertion = request.extensions().get::<DelegationAssertion>().cloned();
    let wire_assertion = request
        .metadata()
        .get_bin("ferro-delegation-bin")
        .map(|value| {
            let bytes = value
                .to_bytes()
                .map_err(|_| Status::permission_denied("malformed CRI delegation metadata"))?;
            DelegationAssertion::from_wire_bytes(&bytes)
                .map_err(|_| Status::permission_denied("malformed CRI delegation token"))
        })
        .transpose()?;
    if extension_assertion.is_some() && wire_assertion.is_some() {
        return Err(Status::permission_denied(
            "multiple CRI delegation assertions are not allowed",
        ));
    }
    let assertion = wire_assertion.or(extension_assertion);
    let telemetry = request
        .metadata()
        .get("x-ferrocrate-delegated-principal")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64;
    policy.resolve(transport, assertion, telemetry, action, resource, now)
}

#[allow(clippy::result_large_err)]
fn trusted_transport<T>(request: &Request<T>) -> Result<&TransportPrincipal, Status> {
    let transport = request
        .extensions()
        .get::<TransportPrincipal>()
        .ok_or_else(|| Status::unauthenticated("CRI transport principal unavailable"))?;
    transport
        .revalidate_for_execution()
        .map_err(|error| Status::unauthenticated(format!("CRI peer identity changed: {error}")))?;
    Ok(transport)
}

struct AuthenticatedUnixStream {
    inner: tokio::net::UnixStream,
    principal: TransportPrincipal,
}
impl tonic::transport::server::Connected for AuthenticatedUnixStream {
    type ConnectInfo = TransportPrincipal;
    fn connect_info(&self) -> Self::ConnectInfo {
        self.principal.clone()
    }
}
impl AsyncRead for AuthenticatedUnixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for AuthenticatedUnixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

const RUNTIME_NAME: &str = "ferrocrate";
const RUNTIME_API_VERSION: &str = "v1";

#[derive(Debug, Error)]
pub enum CriError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("image store error: {0}")]
    ImageStore(#[from] ImageStoreError),
    #[error("runtime authorization error: {0}")]
    Runtime(#[from] ferro_core::runtime::RuntimeError),
}

pub struct CriRuntime {
    store: Arc<LocalImageStore>,
    runtime_dir: std::path::PathBuf,
    identity_policy: CriIdentityPolicy,
    authorization: Arc<SurfaceAuthorization>,
}

impl std::fmt::Debug for CriRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CriRuntime").finish_non_exhaustive()
    }
}

impl CriRuntime {
    pub fn new(
        store: Arc<LocalImageStore>,
        authorization: Arc<SurfaceAuthorization>,
    ) -> Self {
        let runtime_dir = std::env::var("FERROCRATE_RUNTIME_DIR")
            .unwrap_or_else(|_| "/var/lib/ferrocrate".to_string());
        Self {
            store,
            runtime_dir: std::path::PathBuf::from(runtime_dir),
            identity_policy: CriIdentityPolicy::transport_only("cri:local-transport"),
            authorization,
        }
    }

    pub fn with_runtime_dir(
        store: Arc<LocalImageStore>,
        runtime_dir: impl Into<std::path::PathBuf>,
        authorization: Arc<SurfaceAuthorization>,
    ) -> Self {
        Self {
            store,
            runtime_dir: runtime_dir.into(),
            identity_policy: CriIdentityPolicy::transport_only("cri:local-transport"),
            authorization,
        }
    }

    pub fn with_identity_policy(mut self, policy: CriIdentityPolicy) -> Self {
        self.identity_policy = policy;
        self
    }

    pub fn with_surface_authorization(mut self, authorization: Arc<SurfaceAuthorization>) -> Self {
        self.authorization = authorization;
        self
    }
}

#[tonic::async_trait]
impl RuntimeService for CriRuntime {
    async fn version(
        &self,
        _request: Request<VersionRequest>,
    ) -> Result<Response<VersionResponse>, Status> {
        Ok(Response::new(VersionResponse {
            version: RUNTIME_API_VERSION.to_string(),
            runtime_name: RUNTIME_NAME.to_string(),
            runtime_version: env!("CARGO_PKG_VERSION").to_string(),
            runtime_api_version: RUNTIME_API_VERSION.to_string(),
        }))
    }

    async fn status(
        &self,
        request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let req = request.into_inner();
        let condition = RuntimeCondition {
            r#type: "RuntimeReady".to_string(),
            status: true,
            reason: "Ready".to_string(),
            message: "FerroCrate CRI shim is ready".to_string(),
        };
        let info = if req.verbose {
            let mut map = std::collections::HashMap::new();
            map.insert("runtimeName".to_string(), RUNTIME_NAME.to_string());
            map.insert(
                "runtimeVersion".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
            );
            map.insert(
                "runtimeApiVersion".to_string(),
                RUNTIME_API_VERSION.to_string(),
            );
            map.insert(
                "runtimeDir".to_string(),
                self.runtime_dir.display().to_string(),
            );
            map
        } else {
            Default::default()
        };
        Ok(Response::new(StatusResponse {
            status: Some(RuntimeStatus {
                conditions: vec![condition],
            }),
            info,
        }))
    }
}

#[tonic::async_trait]
impl ImageService for CriRuntime {
    async fn list_images(
        &self,
        request: Request<ListImagesRequest>,
    ) -> Result<Response<ListImagesResponse>, Status> {
        let req = request.into_inner();
        let filter = req.filter.trim().to_ascii_lowercase();
        let images: Result<Vec<_>, ImageStoreError> = self.store.list_references();
        let images = images.map_err(|err| Status::internal(err.to_string()))?;
        let entries = images
            .into_iter()
            .filter(|record| {
                if filter.is_empty() {
                    true
                } else {
                    record.reference.to_ascii_lowercase().contains(&filter)
                        || record.digest.to_ascii_lowercase().contains(&filter)
                }
            })
            .map(|record| {
                // Extract tags from reference (e.g., "alpine:latest" -> ["alpine:latest"])
                let repo_tags = if record.reference.starts_with("sha256:") {
                    vec![] // Digest reference, no tags
                } else {
                    vec![record.reference.clone()]
                };
                Image {
                    id: record.digest,
                    repo_tags,
                    repo_digests: vec![], // Not tracked in current store
                    size: 0,              // Size not tracked in current store
                    uid: String::new(),
                    username: String::new(),
                }
            })
            .collect();
        Ok(Response::new(ListImagesResponse { images: entries }))
    }

    async fn image_status(
        &self,
        request: Request<ImageStatusRequest>,
    ) -> Result<Response<ImageStatusResponse>, Status> {
        let req = request.into_inner();
        let image_spec = req
            .image
            .ok_or_else(|| Status::invalid_argument("image spec is required"))?;

        // Try to find image by reference or digest
        let images = self
            .store
            .list_references()
            .map_err(|err| Status::internal(err.to_string()))?;

        let found = images
            .iter()
            .find(|img| img.digest == image_spec.image || img.reference == image_spec.image);

        match found {
            Some(record) => {
                let repo_tags = if record.reference.starts_with("sha256:") {
                    vec![]
                } else {
                    vec![record.reference.clone()]
                };
                let info = if req.verbose {
                    let mut map = std::collections::HashMap::new();
                    map.insert("reference".to_string(), record.reference.clone());
                    map.insert("digest".to_string(), record.digest.clone());
                    map.insert(
                        "manifestMediaType".to_string(),
                        record.manifest_media_type.clone(),
                    );
                    map.insert(
                        "createdAtUnix".to_string(),
                        record.created_at_unix.to_string(),
                    );
                    map
                } else {
                    Default::default()
                };
                Ok(Response::new(ImageStatusResponse {
                    image: Some(Image {
                        id: record.digest.clone(),
                        repo_tags,
                        repo_digests: vec![],
                        size: 0,
                        uid: String::new(),
                        username: String::new(),
                    }),
                    info,
                }))
            }
            None => Err(Status::not_found(format!(
                "image {} not found",
                image_spec.image
            ))),
        }
    }

    async fn pull_image(
        &self,
        request: Request<PullImageRequest>,
    ) -> Result<Response<PullImageResponse>, Status> {
        let image = request
            .get_ref()
            .image
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("image spec is required"))?
            .image
            .clone();
        if image.trim().is_empty() {
            return Err(Status::invalid_argument("image spec is required"));
        }
        trusted_transport(&request)?;
        // Resolve delegation before registry I/O. The canonical reference is
        // the exact scoped resource; the later inspection pins its digest.
        let canonical = ferro_core::image_tagging::canonicalize_reference(&image)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let identity = resolve_request_identity(
            &self.identity_policy,
            &request,
            Action::ImagePull,
            &canonical,
        )?;
        let inspect_image = image.clone();
        let binding = tokio::task::spawn_blocking(move || {
            ferro_core::image_fetch::inspect_image_binding(&inspect_image)
        })
        .await
        .map_err(|error| Status::internal(format!("image inspection task failed: {error}")))?
        .map_err(map_image_fetch_error)?;
        if binding.reference != canonical {
            return Err(Status::failed_precondition(
                "registry binding changed canonical image reference",
            ));
        }
        let origin = identity.request_origin();
        let proof = self
            .authorization
            .authorize_image_binding(
                origin,
                Action::ImagePull,
                &binding.reference,
                &binding.digest,
                1,
            )
            .map_err(|denial| Status::permission_denied(denial.to_string()))?;

        let runtime_dir = self.runtime_dir.clone();
        let store = self.store.clone();
        let pulled = tokio::task::spawn_blocking(move || {
            ferro_core::image_fetch::pull_image_with_store_authorized(
                &runtime_dir,
                &image,
                &binding.reference,
                &binding.digest,
                &store,
                proof,
            )
        })
        .await
        .map_err(|error| Status::internal(format!("image pull task failed: {error}")))?
        .map_err(map_image_fetch_error)?;

        Ok(Response::new(PullImageResponse {
            image_ref: pulled.reference,
        }))
    }

    async fn remove_image(
        &self,
        request: Request<RemoveImageRequest>,
    ) -> Result<Response<RemoveImageResponse>, Status> {
        let image = request
            .get_ref()
            .image
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("image spec is required"))?
            .image
            .clone();
        let image = image.trim();
        if image.is_empty() {
            return Err(Status::invalid_argument("image spec is required"));
        }
        trusted_transport(&request)?;
        let canonical = ferro_core::image_tagging::canonicalize_reference(image).ok();
        let records = self
            .store
            .list_references()
            .map_err(|err| Status::internal(err.to_string()))?;
        let targets: Vec<_> = records
            .into_iter()
            .filter(|record| {
                record.reference == image
                    || canonical.as_deref() == Some(record.reference.as_str())
                    || (image.starts_with("sha256:") && record.digest == image)
            })
            .collect();
        if targets.is_empty() {
            return Err(Status::not_found(format!("image {} not found", image)));
        }
        if targets.len() != 1 {
            return Err(Status::failed_precondition(
                "digest resolves to multiple references; delete an immutable reference",
            ));
        }
        let record = &targets[0];
        let identity = resolve_request_identity(
            &self.identity_policy,
            &request,
            Action::ImageDelete,
            &record.reference,
        )?;
        let proof = self
            .authorization
            .authorize_image_binding(
                identity.request_origin(),
                Action::ImageDelete,
                &record.reference,
                &record.digest,
                1,
            )
            .map_err(|denial| Status::permission_denied(denial.to_string()))?;
        self.store
            .remove_reference_authorized(&record.reference, &record.digest, proof)
            .map_err(|err| Status::internal(err.to_string()))?;

        Ok(Response::new(RemoveImageResponse {}))
    }

    async fn image_fs_info(
        &self,
        _request: Request<ImageFsInfoRequest>,
    ) -> Result<Response<ImageFsInfoResponse>, Status> {
        let images_dir = self.runtime_dir.join("images");
        let usage = collect_fs_usage(&images_dir)?;
        Ok(Response::new(ImageFsInfoResponse {
            image_filesystems: vec![usage],
        }))
    }
}

fn map_image_fetch_error(err: ferro_core::image_fetch::ImageFetchError) -> Status {
    let msg = err.to_string();
    if msg.contains("invalid image reference") {
        Status::invalid_argument(msg)
    } else {
        Status::internal(msg)
    }
}

#[allow(clippy::result_large_err)]
fn collect_fs_usage(path: &Path) -> Result<FilesystemUsage, Status> {
    if !path.exists() {
        fs::create_dir_all(path)
            .map_err(|err| Status::internal(format!("create images dir: {err}")))?;
    }
    let (used_bytes, inodes_used) = measure_tree_usage(path)
        .map_err(|err| Status::internal(format!("measure image filesystem usage: {err}")))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(FilesystemUsage {
        timestamp,
        fs_id: path.display().to_string(),
        mountpoint: path.display().to_string(),
        used_bytes,
        inodes_used,
    })
}

#[cfg(unix)]
fn measure_tree_usage(path: &Path) -> Result<(u64, u64), std::io::Error> {
    use std::collections::HashSet;
    use std::os::unix::fs::MetadataExt;

    fn visit(
        path: &Path,
        bytes: &mut u64,
        inodes: &mut HashSet<u64>,
    ) -> Result<(), std::io::Error> {
        let md = fs::symlink_metadata(path)?;
        inodes.insert(md.ino());
        if md.is_file() {
            *bytes = bytes.saturating_add(md.len());
            return Ok(());
        }
        if !md.is_dir() {
            return Ok(());
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            visit(&entry.path(), bytes, inodes)?;
        }
        Ok(())
    }

    let mut used_bytes = 0u64;
    let mut inodes = HashSet::new();
    visit(path, &mut used_bytes, &mut inodes)?;
    Ok((used_bytes, inodes.len() as u64))
}

#[cfg(not(unix))]
fn measure_tree_usage(path: &Path) -> Result<(u64, u64), std::io::Error> {
    fn visit(path: &Path, bytes: &mut u64, entries: &mut u64) -> Result<(), std::io::Error> {
        let md = fs::symlink_metadata(path)?;
        *entries = entries.saturating_add(1);
        if md.is_file() {
            *bytes = bytes.saturating_add(md.len());
            return Ok(());
        }
        if !md.is_dir() {
            return Ok(());
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            visit(&entry.path(), bytes, entries)?;
        }
        Ok(())
    }

    let mut used_bytes = 0u64;
    let mut entries = 0u64;
    visit(path, &mut used_bytes, &mut entries)?;
    Ok((used_bytes, entries))
}

pub async fn serve(socket_path: impl AsRef<Path>) -> Result<(), CriError> {
    serve_with_identity_policy(
        socket_path,
        CriIdentityPolicy::transport_only("cri:local-transport"),
    )
    .await
}

pub async fn serve_with_identity_policy(
    socket_path: impl AsRef<Path>,
    identity_policy: CriIdentityPolicy,
) -> Result<(), CriError> {
    let socket_path = socket_path.as_ref();
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        let _ = fs::remove_file(socket_path);
    }

    let uds = UnixListener::bind(socket_path)?;
    let incoming = UnixListenerStream::new(uds).map(|accepted| {
        accepted.and_then(|stream| {
            PrincipalResolver::from_cri_peer_credentials(&stream)
                .map(|principal| AuthenticatedUnixStream {
                    inner: stream,
                    principal,
                })
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))
        })
    });
    let runtime_dir = std::env::var("FERROCRATE_RUNTIME_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrocrate".to_string());
    let store = LocalImageStore::open(Path::new(&runtime_dir).join("images"))?;
    let store = Arc::new(store);
    let control_runtime = ferro_core::runtime::ContainerRuntime::new(Path::new(&runtime_dir))?;
    let authorization = Arc::new(control_runtime.surface_authorization()?);
    let runtime = CriRuntime::new(store.clone(), Arc::clone(&authorization))
        .with_identity_policy(identity_policy.clone());

    tonic::transport::Server::builder()
        .add_service(RuntimeServiceServer::new(runtime))
        .add_service(ImageServiceServer::new(
            CriRuntime::new(store, authorization).with_identity_policy(identity_policy),
        ))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{
        ImageFsInfoRequest, ImageSpec, ImageStatusRequest, ListImagesRequest, PullImageRequest,
        RemoveImageRequest,
    };
    use tonic::Request;

    fn test_surface_authorization() -> Arc<SurfaceAuthorization> {
        let root = tempfile::tempdir().expect("authorization runtime").keep();
        let runtime = ferro_core::runtime::ContainerRuntime::new(&root).expect("test runtime");
        Arc::new(runtime.surface_authorization().expect("surface authorization"))
    }

    fn authenticated<T>(message: T) -> Request<T> {
        let (peer, _other) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        let principal = PrincipalResolver::from_cri_peer_credentials(&peer)
            .expect("resolve test transport principal");
        let mut request = Request::new(message);
        request.extensions_mut().insert(principal);
        request
    }

    // Helper to create a test runtime with a temporary image store
    async fn create_test_runtime() -> CriRuntime {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open test store");
        CriRuntime::new(Arc::new(store), test_surface_authorization())
    }

    // Helper to populate test store with sample images
    async fn populate_test_store(store: &LocalImageStore) {
        store
            .put_reference(
                "alpine:latest",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "application/vnd.oci.image.manifest.v1+json",
                r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#,
            )
            .expect("put alpine");

        store
            .put_reference(
                "ghcr.io/test/app:v1.0",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "application/vnd.oci.image.manifest.v1+json",
                r#"{"schemaVersion":2}"#,
            )
            .expect("put test app");

        store
            .put_reference(
                "digest-only",
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "application/vnd.oci.image.manifest.v1+json",
                r#"{"schemaVersion":2}"#,
            )
            .expect("put digest reference");
    }

    #[tokio::test]
    async fn version_returns_correct_runtime_info() {
        let runtime = create_test_runtime().await;
        let request = Request::new(VersionRequest::default());

        let response = runtime
            .version(request)
            .await
            .expect("version should succeed");

        let inner = response.into_inner();
        assert_eq!(inner.version, "v1");
        assert_eq!(inner.runtime_name, "ferrocrate");
        assert!(!inner.runtime_version.is_empty());
        assert_eq!(inner.runtime_api_version, "v1");
    }

    #[tokio::test]
    async fn status_returns_runtime_ready_condition() {
        let runtime = create_test_runtime().await;
        let request = Request::new(StatusRequest { verbose: false });

        let response = runtime
            .status(request)
            .await
            .expect("status should succeed");

        let inner = response.into_inner();
        assert!(inner.status.is_some());

        let status = inner.status.unwrap();
        assert_eq!(status.conditions.len(), 1);

        let condition = &status.conditions[0];
        assert_eq!(condition.r#type, "RuntimeReady");
        assert!(condition.status);
        assert_eq!(condition.reason, "Ready");
        assert_eq!(condition.message, "FerroCrate CRI shim is ready");
    }

    #[tokio::test]
    async fn status_returns_runtime_ready_condition_with_verbose() {
        let runtime = create_test_runtime().await;
        let request = Request::new(StatusRequest { verbose: true });

        let response = runtime
            .status(request)
            .await
            .expect("status should succeed");

        let inner = response.into_inner();
        assert!(inner.status.is_some());
        assert_eq!(inner.status.unwrap().conditions.len(), 1);
        assert_eq!(
            inner.info.get("runtimeName"),
            Some(&"ferrocrate".to_string())
        );
        assert!(inner.info.contains_key("runtimeVersion"));
        assert_eq!(inner.info.get("runtimeApiVersion"), Some(&"v1".to_string()));
        assert!(inner.info.contains_key("runtimeDir"));
    }

    #[tokio::test]
    async fn mutating_rpc_without_transport_connect_info_fails_closed() {
        let runtime = create_test_runtime().await;
        let request = Request::new(RemoveImageRequest {
            image: Some(ImageSpec {
                image: "missing:latest".into(),
            }),
        });

        let error = runtime
            .remove_image(request)
            .await
            .expect_err("missing connect identity must be rejected");

        assert_eq!(error.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn list_images_returns_empty_list_when_store_empty() {
        let runtime = create_test_runtime().await;
        let request = Request::new(ListImagesRequest::default());

        let response = runtime
            .list_images(request)
            .await
            .expect("list_images should succeed");

        let inner = response.into_inner();
        assert!(inner.images.is_empty());
    }

    #[tokio::test]
    async fn list_images_returns_all_stored_images() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open test store");
        populate_test_store(&store).await;

        let runtime = CriRuntime::new(Arc::new(store), test_surface_authorization());
        let request = Request::new(ListImagesRequest::default());

        let response = runtime
            .list_images(request)
            .await
            .expect("list_images should succeed");

        let inner = response.into_inner();
        assert_eq!(inner.images.len(), 3);

        // Verify alpine:latest appears with tag
        let alpine = &inner.images[0];
        assert_eq!(
            alpine.id,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(alpine.repo_tags, vec!["alpine:latest"]);
        assert_eq!(alpine.size, 0);

        // Verify digest-only reference (sorted alphabetically: digest-only comes before ghcr.io)
        let digest_only = &inner.images[1];
        assert!(digest_only.id.starts_with("sha256:cccccccc") && digest_only.id.len() == 71);
        assert_eq!(digest_only.repo_tags, vec!["digest-only"]); // Has tag because reference doesn't start with "sha256:"

        // Verify ghcr.io/test/app:v1.0 appears with tag
        let test_app = &inner.images[2];
        assert_eq!(
            test_app.id,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(test_app.repo_tags, vec!["ghcr.io/test/app:v1.0"]);
    }

    #[tokio::test]
    async fn list_images_handles_filter_parameter() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open test store");
        populate_test_store(&store).await;

        let runtime = CriRuntime::new(Arc::new(store), test_surface_authorization());

        let request = Request::new(ListImagesRequest {
            filter: "alpine".to_string(),
        });

        let response = runtime
            .list_images(request)
            .await
            .expect("list_images with filter should succeed");

        let inner = response.into_inner();
        assert_eq!(inner.images.len(), 1);
        assert_eq!(inner.images[0].repo_tags, vec!["alpine:latest"]);
    }

    #[tokio::test]
    async fn image_status_returns_not_found_for_missing_image() {
        let runtime = create_test_runtime().await;
        let request = Request::new(ImageStatusRequest {
            image: Some(ImageSpec {
                image: "nonexistent:latest".to_string(),
            }),
            verbose: false,
        });

        let result = runtime.image_status(request).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
        assert!(err.message().contains("not found"));
    }

    #[tokio::test]
    async fn image_status_returns_invalid_argument_for_missing_image_spec() {
        let runtime = create_test_runtime().await;
        let request = Request::new(ImageStatusRequest {
            image: None, // Missing image spec
            verbose: false,
        });

        let result = runtime.image_status(request).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("image spec is required"));
    }

    #[tokio::test]
    async fn image_status_finds_image_by_reference() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open test store");
        populate_test_store(&store).await;

        let runtime = CriRuntime::new(Arc::new(store), test_surface_authorization());
        let request = Request::new(ImageStatusRequest {
            image: Some(ImageSpec {
                image: "alpine:latest".to_string(),
            }),
            verbose: false,
        });

        let response = runtime
            .image_status(request)
            .await
            .expect("image_status should succeed");

        let inner = response.into_inner();
        assert!(inner.image.is_some());

        let image = inner.image.unwrap();
        assert_eq!(
            image.id,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(image.repo_tags, vec!["alpine:latest"]);
        assert_eq!(image.size, 0);
    }

    #[tokio::test]
    async fn image_status_finds_image_by_digest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open test store");
        populate_test_store(&store).await;

        let runtime = CriRuntime::new(Arc::new(store), test_surface_authorization());
        let request = Request::new(ImageStatusRequest {
            image: Some(ImageSpec {
                image: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            }),
            verbose: false,
        });

        let response = runtime
            .image_status(request)
            .await
            .expect("image_status should succeed");

        let inner = response.into_inner();
        assert!(inner.image.is_some());

        let image = inner.image.unwrap();
        assert_eq!(
            image.id,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(image.repo_tags, vec!["ghcr.io/test/app:v1.0"]);
    }

    #[tokio::test]
    async fn image_status_returns_no_tags_for_digest_reference() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open test store");
        populate_test_store(&store).await;

        let runtime = CriRuntime::new(Arc::new(store), test_surface_authorization());
        let request = Request::new(ImageStatusRequest {
            image: Some(ImageSpec {
                image: "digest-only".to_string(),
            }),
            verbose: false,
        });

        let response = runtime
            .image_status(request)
            .await
            .expect("image_status should succeed");

        let inner = response.into_inner();
        assert!(inner.image.is_some());

        let image = inner.image.unwrap();
        assert_eq!(
            image.id,
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert_eq!(image.repo_tags, vec!["digest-only"]); // Has tag because reference doesn't start with "sha256:"
        assert!(image.repo_digests.is_empty());
    }

    #[tokio::test]
    async fn pull_image_requires_image_spec() {
        let runtime = create_test_runtime().await;
        let request = Request::new(PullImageRequest {
            image: None,
            auth: Default::default(),
            sandbox_config: String::new(),
        });

        let result = runtime.pull_image(request).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("image spec is required"));
    }

    #[tokio::test]
    async fn remove_image_removes_existing_reference() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open test store");
        populate_test_store(&store).await;
        let runtime = CriRuntime::new(Arc::new(store), test_surface_authorization());

        let request = authenticated(RemoveImageRequest {
            image: Some(ImageSpec {
                image: "alpine:latest".to_string(),
            }),
        });

        runtime
            .remove_image(request)
            .await
            .expect("remove_image should succeed");

        let status = runtime
            .image_status(Request::new(ImageStatusRequest {
                image: Some(ImageSpec {
                    image: "alpine:latest".to_string(),
                }),
                verbose: false,
            }))
            .await;
        assert!(status.is_err());
        assert_eq!(status.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn remove_image_returns_not_found_when_missing() {
        let runtime = create_test_runtime().await;
        let request = authenticated(RemoveImageRequest {
            image: Some(ImageSpec {
                image: "alpine:latest".to_string(),
            }),
        });

        let result = runtime.remove_image(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn cri_runtime_debug_impl_is_non_exhaustive() {
        let runtime = create_test_runtime().await;
        let debug_str = format!("{:?}", runtime);
        // Debug output should contain struct name
        assert!(debug_str.contains("CriRuntime"));
        // Should be marked as non_exhaustive
        assert!(debug_str.contains(".."));
    }

    #[tokio::test]
    async fn cri_runtime_new_with_arc_store() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open test store");
        let arc_store = Arc::new(store);

        let runtime = CriRuntime::new(arc_store.clone(), test_surface_authorization());
        let request = Request::new(VersionRequest::default());

        // Verify runtime works with Arc store
        let response = runtime
            .version(request)
            .await
            .expect("version should succeed");
        assert_eq!(response.into_inner().runtime_name, "ferrocrate");
    }

    #[tokio::test]
    async fn list_images_with_digest_references_only() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open test store");

        // Only add digest-based references
        store
            .put_reference(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "application/vnd.oci.image.manifest.v1+json",
                r#"{"schemaVersion":2}"#,
            )
            .expect("put digest");

        let runtime = CriRuntime::new(Arc::new(store), test_surface_authorization());
        let request = Request::new(ListImagesRequest::default());

        let response = runtime
            .list_images(request)
            .await
            .expect("list_images should succeed");

        let inner = response.into_inner();
        assert_eq!(inner.images.len(), 1);
        // Digest references have empty repo_tags
        assert!(inner.images[0].repo_tags.is_empty());
    }

    #[tokio::test]
    async fn image_status_with_verbose_flag() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open test store");
        populate_test_store(&store).await;

        let runtime = CriRuntime::new(Arc::new(store), test_surface_authorization());
        let request = Request::new(ImageStatusRequest {
            image: Some(ImageSpec {
                image: "alpine:latest".to_string(),
            }),
            verbose: true, // Verbose flag
        });

        let response = runtime
            .image_status(request)
            .await
            .expect("image_status should succeed");

        let inner = response.into_inner();
        assert!(inner.image.is_some());
        assert_eq!(
            inner.info.get("reference"),
            Some(&"alpine:latest".to_string())
        );
        assert!(inner.info.contains_key("digest"));
        assert!(inner.info.contains_key("manifestMediaType"));
        assert!(inner.info.contains_key("createdAtUnix"));
    }

    #[tokio::test]
    async fn list_images_returns_images_sorted_by_reference() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open test store");

        // Add images in non-alphabetical order
        store
            .put_reference(
                "zebra:latest",
                "sha256:zzzz",
                "application/vnd.oci.image.manifest.v1+json",
                r#"{"schemaVersion":2}"#,
            )
            .expect("put zebra");

        store
            .put_reference(
                "alpine:latest",
                "sha256:aaaa",
                "application/vnd.oci.image.manifest.v1+json",
                r#"{"schemaVersion":2}"#,
            )
            .expect("put alpine");

        store
            .put_reference(
                "mongo:latest",
                "sha256:mmmm",
                "application/vnd.oci.image.manifest.v1+json",
                r#"{"schemaVersion":2}"#,
            )
            .expect("put mongo");

        let runtime = CriRuntime::new(Arc::new(store), test_surface_authorization());
        let request = Request::new(ListImagesRequest::default());

        let response = runtime
            .list_images(request)
            .await
            .expect("list_images should succeed");

        let inner = response.into_inner();
        // Images should be sorted by reference (from store.list_references)
        assert_eq!(inner.images.len(), 3);
        assert_eq!(inner.images[0].repo_tags[0], "alpine:latest");
        assert_eq!(inner.images[1].repo_tags[0], "mongo:latest");
        assert_eq!(inner.images[2].repo_tags[0], "zebra:latest");
    }

    #[tokio::test]
    async fn image_fs_info_reports_runtime_images_usage() {
        let temp = tempfile::tempdir().expect("tempdir");
        let images_root = temp.path().join("images");
        fs::create_dir_all(images_root.join("sub")).expect("create images dirs");
        fs::write(images_root.join("blob-a"), b"abcd").expect("write blob-a");
        fs::write(images_root.join("sub/blob-b"), b"123456").expect("write blob-b");

        let store = LocalImageStore::open(images_root.clone()).expect("open store");
        let runtime = CriRuntime::with_runtime_dir(
            Arc::new(store),
            temp.path(),
            test_surface_authorization(),
        );

        let response = runtime
            .image_fs_info(Request::new(ImageFsInfoRequest {}))
            .await
            .expect("image_fs_info should succeed");

        let inner = response.into_inner();
        assert_eq!(inner.image_filesystems.len(), 1);
        let fs_usage = &inner.image_filesystems[0];
        assert_eq!(fs_usage.mountpoint, images_root.display().to_string());
        assert_eq!(fs_usage.fs_id, images_root.display().to_string());
        assert!(fs_usage.used_bytes >= 10);
        assert!(fs_usage.inodes_used > 0);
    }
}
