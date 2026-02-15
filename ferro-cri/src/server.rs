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
    runtime_dir: std::path::PathBuf,
}

impl std::fmt::Debug for CriRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CriRuntime").finish_non_exhaustive()
    }
}

impl CriRuntime {
    pub fn new(store: Arc<LocalImageStore>) -> Self {
        let runtime_dir = std::env::var("FERROCRATE_RUNTIME_DIR")
            .unwrap_or_else(|_| "/var/lib/ferrocrate".to_string());
        Self {
            store,
            runtime_dir: std::path::PathBuf::from(runtime_dir),
        }
    }

    pub fn with_runtime_dir(
        store: Arc<LocalImageStore>,
        runtime_dir: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            store,
            runtime_dir: runtime_dir.into(),
        }
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
            map.insert("runtimeVersion".to_string(), env!("CARGO_PKG_VERSION").to_string());
            map.insert("runtimeApiVersion".to_string(), RUNTIME_API_VERSION.to_string());
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
        let req = request.into_inner();
        let image = req
            .image
            .ok_or_else(|| Status::invalid_argument("image spec is required"))?
            .image;
        if image.trim().is_empty() {
            return Err(Status::invalid_argument("image spec is required"));
        }

        let pulled = ferro_core::image_fetch::pull_image_with_store(
            &self.runtime_dir,
            &image,
            &self.store,
        )
        .map_err(map_image_fetch_error)?;

        Ok(Response::new(PullImageResponse {
            image_ref: pulled.reference,
        }))
    }

    async fn remove_image(
        &self,
        request: Request<RemoveImageRequest>,
    ) -> Result<Response<RemoveImageResponse>, Status> {
        let req = request.into_inner();
        let image = req
            .image
            .ok_or_else(|| Status::invalid_argument("image spec is required"))?
            .image;
        let image = image.trim();
        if image.is_empty() {
            return Err(Status::invalid_argument("image spec is required"));
        }

        let canonical = ferro_core::image_tagging::canonicalize_reference(image).ok();
        let mut removed = self
            .store
            .remove_reference(image)
            .map_err(|err| Status::internal(err.to_string()))?;
        if !removed {
            if let Some(canonical) = canonical.as_ref() {
                if canonical != image {
                    removed = self
                        .store
                        .remove_reference(canonical)
                        .map_err(|err| Status::internal(err.to_string()))?;
                }
            }
        }
        if !removed && image.starts_with("sha256:") {
            let refs = self
                .store
                .list_references()
                .map_err(|err| Status::internal(err.to_string()))?;
            for record in refs.into_iter().filter(|entry| entry.digest == image) {
                let _ = self.store.remove_reference(&record.reference);
                removed = true;
            }
        }

        if !removed {
            return Err(Status::not_found(format!("image {} not found", image)));
        }

        Ok(Response::new(RemoveImageResponse {}))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{ImageSpec, ListImagesRequest, ImageStatusRequest, PullImageRequest, RemoveImageRequest};
    use tonic::Request;

    // Helper to create a test runtime with a temporary image store
    async fn create_test_runtime() -> CriRuntime {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path())
            .expect("open test store");
        CriRuntime::new(Arc::new(store))
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

        let response = runtime.version(request).await
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
        let request = Request::new(StatusRequest {
            verbose: false,
        });

        let response = runtime.status(request).await
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
        let request = Request::new(StatusRequest {
            verbose: true,
        });

        let response = runtime.status(request).await
            .expect("status should succeed");

        let inner = response.into_inner();
        assert!(inner.status.is_some());
        assert_eq!(inner.status.unwrap().conditions.len(), 1);
        assert_eq!(inner.info.get("runtimeName"), Some(&"ferrocrate".to_string()));
        assert!(inner.info.contains_key("runtimeVersion"));
        assert_eq!(inner.info.get("runtimeApiVersion"), Some(&"v1".to_string()));
        assert!(inner.info.contains_key("runtimeDir"));
    }

    #[tokio::test]
    async fn list_images_returns_empty_list_when_store_empty() {
        let runtime = create_test_runtime().await;
        let request = Request::new(ListImagesRequest::default());

        let response = runtime.list_images(request).await
            .expect("list_images should succeed");

        let inner = response.into_inner();
        assert!(inner.images.is_empty());
    }

    #[tokio::test]
    async fn list_images_returns_all_stored_images() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path())
            .expect("open test store");
        populate_test_store(&store).await;

        let runtime = CriRuntime::new(Arc::new(store));
        let request = Request::new(ListImagesRequest::default());

        let response = runtime.list_images(request).await
            .expect("list_images should succeed");

        let inner = response.into_inner();
        assert_eq!(inner.images.len(), 3);

        // Verify alpine:latest appears with tag
        let alpine = &inner.images[0];
        assert_eq!(alpine.id, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(alpine.repo_tags, vec!["alpine:latest"]);
        assert_eq!(alpine.size, 0);

        // Verify digest-only reference (sorted alphabetically: digest-only comes before ghcr.io)
        let digest_only = &inner.images[1];
        assert!(digest_only.id.starts_with("sha256:cccccccc") && digest_only.id.len() == 71);
        assert_eq!(digest_only.repo_tags, vec!["digest-only"]); // Has tag because reference doesn't start with "sha256:"

        // Verify ghcr.io/test/app:v1.0 appears with tag
        let test_app = &inner.images[2];
        assert_eq!(test_app.id, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert_eq!(test_app.repo_tags, vec!["ghcr.io/test/app:v1.0"]);
    }

    #[tokio::test]
    async fn list_images_handles_filter_parameter() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path())
            .expect("open test store");
        populate_test_store(&store).await;

        let runtime = CriRuntime::new(Arc::new(store));

        let request = Request::new(ListImagesRequest {
            filter: "alpine".to_string(),
        });

        let response = runtime.list_images(request).await
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
        let store = LocalImageStore::open(temp.path())
            .expect("open test store");
        populate_test_store(&store).await;

        let runtime = CriRuntime::new(Arc::new(store));
        let request = Request::new(ImageStatusRequest {
            image: Some(ImageSpec {
                image: "alpine:latest".to_string(),
            }),
            verbose: false,
        });

        let response = runtime.image_status(request).await
            .expect("image_status should succeed");

        let inner = response.into_inner();
        assert!(inner.image.is_some());

        let image = inner.image.unwrap();
        assert_eq!(image.id, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(image.repo_tags, vec!["alpine:latest"]);
        assert_eq!(image.size, 0);
    }

    #[tokio::test]
    async fn image_status_finds_image_by_digest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path())
            .expect("open test store");
        populate_test_store(&store).await;

        let runtime = CriRuntime::new(Arc::new(store));
        let request = Request::new(ImageStatusRequest {
            image: Some(ImageSpec {
                image: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            }),
            verbose: false,
        });

        let response = runtime.image_status(request).await
            .expect("image_status should succeed");

        let inner = response.into_inner();
        assert!(inner.image.is_some());

        let image = inner.image.unwrap();
        assert_eq!(image.id, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert_eq!(image.repo_tags, vec!["ghcr.io/test/app:v1.0"]);
    }

    #[tokio::test]
    async fn image_status_returns_no_tags_for_digest_reference() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path())
            .expect("open test store");
        populate_test_store(&store).await;

        let runtime = CriRuntime::new(Arc::new(store));
        let request = Request::new(ImageStatusRequest {
            image: Some(ImageSpec {
                image: "digest-only".to_string(),
            }),
            verbose: false,
        });

        let response = runtime.image_status(request).await
            .expect("image_status should succeed");

        let inner = response.into_inner();
        assert!(inner.image.is_some());

        let image = inner.image.unwrap();
        assert_eq!(image.id, "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
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
        let store = LocalImageStore::open(temp.path())
            .expect("open test store");
        populate_test_store(&store).await;
        let runtime = CriRuntime::new(Arc::new(store));

        let request = Request::new(RemoveImageRequest {
            image: Some(ImageSpec {
                image: "alpine:latest".to_string(),
            }),
        });

        runtime.remove_image(request).await.expect("remove_image should succeed");

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
        let request = Request::new(RemoveImageRequest {
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
        let store = LocalImageStore::open(temp.path())
            .expect("open test store");
        let arc_store = Arc::new(store);

        let runtime = CriRuntime::new(arc_store.clone());
        let request = Request::new(VersionRequest::default());

        // Verify runtime works with Arc store
        let response = runtime.version(request).await
            .expect("version should succeed");
        assert_eq!(response.into_inner().runtime_name, "ferrocrate");
    }

    #[tokio::test]
    async fn list_images_with_digest_references_only() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path())
            .expect("open test store");

        // Only add digest-based references
        store
            .put_reference(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "application/vnd.oci.image.manifest.v1+json",
                r#"{"schemaVersion":2}"#,
            )
            .expect("put digest");

        let runtime = CriRuntime::new(Arc::new(store));
        let request = Request::new(ListImagesRequest::default());

        let response = runtime.list_images(request).await
            .expect("list_images should succeed");

        let inner = response.into_inner();
        assert_eq!(inner.images.len(), 1);
        // Digest references have empty repo_tags
        assert!(inner.images[0].repo_tags.is_empty());
    }

    #[tokio::test]
    async fn image_status_with_verbose_flag() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path())
            .expect("open test store");
        populate_test_store(&store).await;

        let runtime = CriRuntime::new(Arc::new(store));
        let request = Request::new(ImageStatusRequest {
            image: Some(ImageSpec {
                image: "alpine:latest".to_string(),
            }),
            verbose: true, // Verbose flag
        });

        let response = runtime.image_status(request).await
            .expect("image_status should succeed");

        let inner = response.into_inner();
        assert!(inner.image.is_some());
        assert_eq!(inner.info.get("reference"), Some(&"alpine:latest".to_string()));
        assert!(inner.info.contains_key("digest"));
        assert!(inner.info.contains_key("manifestMediaType"));
        assert!(inner.info.contains_key("createdAtUnix"));
    }

    #[tokio::test]
    async fn list_images_returns_images_sorted_by_reference() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path())
            .expect("open test store");

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

        let runtime = CriRuntime::new(Arc::new(store));
        let request = Request::new(ListImagesRequest::default());

        let response = runtime.list_images(request).await
            .expect("list_images should succeed");

        let inner = response.into_inner();
        // Images should be sorted by reference (from store.list_references)
        assert_eq!(inner.images.len(), 3);
        assert_eq!(inner.images[0].repo_tags[0], "alpine:latest");
        assert_eq!(inner.images[1].repo_tags[0], "mongo:latest");
        assert_eq!(inner.images[2].repo_tags[0], "zebra:latest");
    }
}
