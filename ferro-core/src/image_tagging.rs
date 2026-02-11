use crate::image_store::{ImageRecord, ImageStoreError, LocalImageStore};
use crate::registry::{RegistryError, parse_image_reference};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImageTaggingError {
    #[error("invalid image reference: {0}")]
    InvalidReference(#[from] RegistryError),
    #[error("image store error: {0}")]
    Store(#[from] ImageStoreError),
    #[error("source image not found: {0}")]
    SourceNotFound(String),
}

pub fn canonicalize_reference(reference: &str) -> Result<String, ImageTaggingError> {
    let parsed = parse_image_reference(reference)?;
    Ok(parsed.canonical())
}

pub fn resolve_reference(
    store: &LocalImageStore,
    reference: &str,
) -> Result<Option<ImageRecord>, ImageTaggingError> {
    let canonical = canonicalize_reference(reference)?;
    let record = store.resolve_reference(&canonical)?;
    Ok(record)
}

pub fn tag_image(
    store: &LocalImageStore,
    source_reference: &str,
    target_reference: &str,
) -> Result<(), ImageTaggingError> {
    let source_canonical = canonicalize_reference(source_reference)?;
    let target_canonical = canonicalize_reference(target_reference)?;

    let source = store
        .resolve_reference(&source_canonical)?
        .ok_or_else(|| ImageTaggingError::SourceNotFound(source_canonical.clone()))?;

    store.put_reference(
        &target_canonical,
        &source.digest,
        &source.manifest_media_type,
        &source.manifest_json,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{canonicalize_reference, resolve_reference, tag_image};
    use crate::image_store::LocalImageStore;

    #[test]
    fn canonicalizes_reference_with_defaults() {
        let canonical = canonicalize_reference("alpine").expect("canonicalize");
        assert_eq!(canonical, "registry-1.docker.io/library/alpine:latest");
    }

    #[test]
    fn tags_existing_image_to_new_reference() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open store");

        store
            .put_reference(
                "registry-1.docker.io/library/alpine:latest",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "application/vnd.oci.image.manifest.v1+json",
                "{\"schemaVersion\":2}",
            )
            .expect("seed source image");

        tag_image(&store, "alpine", "ghcr.io/acme/alpine:stable").expect("tag image");

        let resolved = resolve_reference(&store, "ghcr.io/acme/alpine:stable")
            .expect("resolve should succeed")
            .expect("tag should exist");

        assert_eq!(
            resolved.digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn returns_error_when_source_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open store");

        let err = tag_image(&store, "missing:latest", "acme/new:latest")
            .expect_err("tagging should fail");

        assert!(err.to_string().contains("source image not found"));
    }
}
