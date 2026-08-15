use crate::image_store::{ImageRecord, ImageStoreError, LocalImageStore};
use crate::registry::{parse_image_reference, RegistryError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImageTaggingError {
    #[error("invalid image reference: {0}")]
    InvalidReference(#[from] RegistryError),
    #[error("image store error: {0}")]
    Store(#[from] ImageStoreError),
    #[error("source image not found: {0}")]
    SourceNotFound(String),
    #[error("image tag authorization binding failed: {0}")]
    Authorization(String),
}

#[derive(Clone, Debug)]
pub struct ImageTagPlan {
    source_reference: String,
    target_reference: String,
    source_digest: String,
    manifest_digest: [u8; 32],
    plan_digest: [u8; 32],
}

impl ImageTagPlan {
    pub fn target_reference(&self) -> &str {
        &self.target_reference
    }
    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }
    pub fn generation(&self) -> u64 {
        1
    }
}

pub fn prepare_image_tag(
    store: &LocalImageStore,
    source_reference: &str,
    target_reference: &str,
) -> Result<ImageTagPlan, ImageTaggingError> {
    use sha2::{Digest, Sha256};
    let source_reference = canonicalize_reference(source_reference)?;
    let target_reference = canonicalize_reference(target_reference)?;
    let source = store
        .resolve_reference(&source_reference)?
        .ok_or_else(|| ImageTaggingError::SourceNotFound(source_reference.clone()))?;
    let manifest_digest: [u8; 32] = Sha256::digest(source.manifest_json.as_bytes()).into();
    let mut hash = Sha256::new();
    hash.update(b"ferrocrate/image-tag-plan/v1");
    for value in [&source_reference, &target_reference, &source.digest] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.update(manifest_digest);
    Ok(ImageTagPlan {
        source_reference,
        target_reference,
        source_digest: source.digest,
        manifest_digest,
        plan_digest: hash.finalize().into(),
    })
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

fn tag_image(
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

pub fn execute_image_tag_authorized(
    store: &LocalImageStore,
    plan: ImageTagPlan,
    permit: crate::authorization::surface::SurfacePermit,
) -> Result<(), ImageTaggingError> {
    use sha2::{Digest, Sha256};
    crate::authorization::surface::SurfaceAuthorization::validate_execution(
        &permit,
        crate::authorization::Action::ImageTag,
        crate::authorization::ResourceKind::Image,
        plan.target_reference(),
        plan.generation(),
    )
    .map_err(|error| ImageTaggingError::Authorization(error.to_string()))?;
    if permit.proof().canonical().operation_plan_digest() != Some(&plan.plan_digest()) {
        permit
            .finish(false)
            .map_err(|error| ImageTaggingError::Authorization(error.to_string()))?;
        return Err(ImageTaggingError::Authorization(
            "image tag plan does not match proof".to_string(),
        ));
    }
    let source = store
        .resolve_reference(&plan.source_reference)?
        .ok_or_else(|| ImageTaggingError::SourceNotFound(plan.source_reference.clone()))?;
    if source.digest != plan.source_digest
        || <[u8; 32]>::from(Sha256::digest(source.manifest_json.as_bytes())) != plan.manifest_digest
    {
        permit
            .finish(false)
            .map_err(|error| ImageTaggingError::Authorization(error.to_string()))?;
        return Err(ImageTaggingError::Authorization(
            "image tag source changed after authorization".to_string(),
        ));
    }
    match store.put_reference(
        &plan.target_reference,
        &source.digest,
        &source.manifest_media_type,
        &source.manifest_json,
    ) {
        Ok(()) => permit
            .finish(true)
            .map_err(|error| ImageTaggingError::Authorization(error.to_string())),
        Err(error) => {
            permit
                .finish_unknown()
                .map_err(|finish| ImageTaggingError::Authorization(finish.to_string()))?;
            Err(ImageTaggingError::Store(error))
        }
    }
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
