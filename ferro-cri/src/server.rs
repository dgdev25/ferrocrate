use crate::runtime::image_service_server::{ImageService, ImageServiceServer};
use crate::runtime::runtime_service_server::{RuntimeService, RuntimeServiceServer};
use crate::runtime::{
    ListImagesRequest, ListImagesResponse, RuntimeCondition, RuntimeStatus, StatusRequest,
    StatusResponse, VersionRequest, VersionResponse,
};
use std::fs;
use std::path::Path;
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
}

#[derive(Debug, Default)]
pub struct CriRuntime;

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
        Ok(Response::new(ListImagesResponse { images: Vec::new() }))
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
    let runtime = CriRuntime::default();

    tonic::transport::Server::builder()
        .add_service(RuntimeServiceServer::new(runtime))
        .add_service(ImageServiceServer::new(CriRuntime::default()))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}
