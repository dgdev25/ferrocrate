use crate::docker_auth::resolve_registry_auth;
use crate::image_manifest::parse_image_manifest;
use crate::image_store::LocalImageStore;
use crate::image_tagging::ImageTaggingError;
use crate::registry::RegistryClient;
use crate::registry::parse_image_reference;
use std::fs;
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
}

pub struct ImageFetchResult {
    pub reference: String,
    pub layer_paths: Vec<PathBuf>,
}

pub fn pull_image(runtime_dir: &Path, image: &str) -> Result<ImageFetchResult, ImageFetchError> {
    parse_image_reference(image)?;
    let store = LocalImageStore::open(runtime_dir.join("images"))?;
    let client = RegistryClient::new()?;
    let auth = resolve_registry_auth(image)?;

    let manifest_json = client.pull_manifest_raw(image, auth.as_ref())?;
    let manifest = parse_image_manifest(&manifest_json)?;

    let canonical = crate::image_tagging::canonicalize_reference(image)?;
    store.put_reference(
        &canonical,
        &manifest.config.digest,
        crate::image_manifest::OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        &manifest_json,
    )?;

    let blob_root = runtime_dir.join("images").join("blobs");
    fs::create_dir_all(&blob_root)?;
    let mut layer_paths = Vec::new();

    for layer in &manifest.layers {
        let digest = layer.digest.replace(':', "_");
        let blob_path = blob_root.join(&digest);
        if !blob_path.exists() {
            client.pull_blob_to_file(&canonical, &layer.digest, auth.as_ref(), &blob_path)?;
        }
        layer_paths.push(blob_path);
    }

    Ok(ImageFetchResult {
        reference: canonical,
        layer_paths,
    })
}

pub fn resolve_layer_paths(runtime_dir: &Path, image: &str) -> Result<Vec<PathBuf>, ImageFetchError> {
    parse_image_reference(image)?;
    let store = LocalImageStore::open(runtime_dir.join("images"))?;
    let canonical = crate::image_tagging::canonicalize_reference(image)?;
    let record = store
        .resolve_reference(&canonical)?
        .ok_or_else(|| crate::registry::RegistryError::InvalidReference(canonical.clone()))?;

    let manifest = parse_image_manifest(&record.manifest_json)?;
    let blob_root = runtime_dir.join("images").join("blobs");
    let mut layer_paths = Vec::new();
    for layer in &manifest.layers {
        let digest = layer.digest.replace(':', "_");
        let blob_path = blob_root.join(&digest);
        layer_paths.push(blob_path);
    }
    Ok(layer_paths)
}

#[cfg(test)]
mod tests {
    use super::pull_image;
    use httptest::matchers::request;
    use httptest::responders::status_code;
    use httptest::{Expectation, Server};
    use std::fs;

    #[test]
    fn pulls_manifest_and_layers() {
        let server = Server::run();
        let manifest_json = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":4}]}"#;

        server.expect(
            Expectation::matching(request::method_path("GET", "/v2/library/alpine/manifests/latest"))
                .respond_with(status_code(200).body(manifest_json)),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/v2/library/alpine/blobs/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
                .respond_with(status_code(200).body("TEST")),
        );

        let temp = tempfile::tempdir().expect("tempdir");
        let image = format!("{}/library/alpine", server.addr());
        let result = pull_image(temp.path(), &image).expect("pull image");
        assert_eq!(result.layer_paths.len(), 1);
        let content = fs::read_to_string(&result.layer_paths[0]).expect("blob content");
        assert_eq!(content, "TEST");
    }
}
