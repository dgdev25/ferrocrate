use crate::runtime::image_service_server::{ImageService, ImageServiceServer};
use crate::runtime::runtime_service_server::{RuntimeService, RuntimeServiceServer};
use crate::runtime::{
    Image, ImageStatusRequest, ImageStatusResponse, ListImagesRequest,
    ListImagesResponse, PullImageRequest, PullImageResponse, RemoveImageRequest,
    RemoveImageResponse, RuntimeCondition, RuntimeStatus, StatusRequest, StatusResponse,
    VersionRequest, VersionResponse,
};
use ferro_core::image_store::{ImageStoreError, LocalImageStore};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};

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
}

pub struct CriRuntime {
    store: Arc<LocalImageStore>,
}

impl std::fmt::Debug for CriRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CriRuntime").finish_non_exhaustive()
    }
}

impl CriRuntime {
    pub fn new(store: Arc<LocalImageStore>) -> Self {
        Self { store }
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
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let condition = RuntimeCondition {
            r#type: "RuntimeReady".to_string(),
            status: true,
            reason: "Ready".to_string(),
            message: "FerroCrate CRI shim is ready".to_string(),
        };
        Ok(Response::new(StatusResponse {
            status: Some(RuntimeStatus {
                conditions: vec![condition],
            }),
            info: Default::default(),
        }))
    }
}

#[tonic::async_trait]
impl ImageService for CriRuntime {
    async fn list_images(
        &self,
        _request: Request<ListImagesRequest>,
    ) -> Result<Response<ListImagesResponse>, Status> {
        let images: Result<Vec<_>, ImageStoreError> = self.store.list_references();
        let images = images.map_err(|err| Status::internal(err.to_string()))?;
        let entries = images
            .into_iter()
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
        let image_spec = req.image.ok_or_else(|| {
            Status::invalid_argument("image spec is required")
        })?;

        // Try to find image by reference or digest
        let images = self.store.list_references()
            .map_err(|err| Status::internal(err.to_string()))?;

        let found = images.iter().find(|img| {
            img.digest == image_spec.image || img.reference == image_spec.image
        });

        match found {
            Some(record) => {
                let repo_tags = if record.reference.starts_with("sha256:") {
                    vec![]
                } else {
                    vec![record.reference.clone()]
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
                    info: Default::default(),
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
        _request: Request<PullImageRequest>,
    ) -> Result<Response<PullImageResponse>, Status> {
        // Image pulling requires integration with ferro-core runtime
        // This is a placeholder that returns an error indicating the limitation
        Err(Status::unimplemented(
            "PullImage is not yet implemented. Use 'ferrocrate pull' CLI command instead."
        ))
    }

    async fn remove_image(
        &self,
        _request: Request<RemoveImageRequest>,
    ) -> Result<Response<RemoveImageResponse>, Status> {
        // Image removal requires integration with ferro-core runtime
        // This is a placeholder that returns an error indicating the limitation
        Err(Status::unimplemented(
            "RemoveImage is not yet implemented. Use 'ferrocrate rmi' CLI command instead."
        ))
    }
}

pub async fn serve(socket_path: impl AsRef<Path>) -> Result<(), CriError> {
    let socket_path = socket_path.as_ref();
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        let _ = fs::remove_file(socket_path);
    }

    let uds = UnixListener::bind(socket_path)?;
    let incoming = UnixListenerStream::new(uds);
    let runtime_dir = std::env::var("FERROCRATE_RUNTIME_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrocrate".to_string());
    let store = LocalImageStore::open(Path::new(&runtime_dir).join("images"))?;
    let store = Arc::new(store);
    let runtime = CriRuntime::new(store.clone());

    tonic::transport::Server::builder()
        .add_service(RuntimeServiceServer::new(runtime))
        .add_service(ImageServiceServer::new(CriRuntime::new(store)))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}
