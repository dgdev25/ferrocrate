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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImageSelector {
    Named(String),
    IdPrefix(String),
}

impl ImageSelector {
    pub fn canonical(&self) -> &str {
        match self {
            Self::Named(value) | Self::IdPrefix(value) => value,
        }
    }

    pub fn is_local_only(&self) -> bool {
        matches!(self, Self::IdPrefix(_))
    }
}

pub fn normalize_selector(reference: &str) -> Result<ImageSelector, ImageTaggingError> {
    let bare = reference.strip_prefix("sha256:").unwrap_or(reference);
    let sha256 = reference.starts_with("sha256:");
    let id_shaped = bare.len() >= 4
        && bare.len() <= 64
        && bare.bytes().all(|byte| byte.is_ascii_hexdigit())
        && (!sha256 || bare.len() == 64);
    if id_shaped {
        return Ok(ImageSelector::IdPrefix(bare.to_ascii_lowercase()));
    }
    Ok(ImageSelector::Named(canonicalize_reference(reference)?))
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
    let selector = normalize_selector(source_reference)?;
    let source = match &selector {
        ImageSelector::Named(canonical) => store.resolve_reference(canonical)?,
        ImageSelector::IdPrefix(prefix) => store.resolve_id_prefix(prefix)?,
    }
    .ok_or_else(|| ImageTaggingError::SourceNotFound(source_reference.to_string()))?;
    let source_reference = match selector {
        ImageSelector::Named(canonical) => canonical,
        ImageSelector::IdPrefix(_) => source.digest.clone(),
    };
    let target_reference = canonicalize_reference(target_reference)?;
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
    let selector = normalize_selector(reference)?;
    let record = match &selector {
        ImageSelector::Named(canonical) => store.resolve_reference(canonical)?,
        ImageSelector::IdPrefix(prefix) => store.resolve_id_prefix(prefix)?,
    };
    Ok(record)
}

#[allow(dead_code)]
fn tag_image(
    store: &LocalImageStore,
    authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
    source_reference: &str,
    target_reference: &str,
) -> Result<(), ImageTaggingError> {
    let source_canonical = canonicalize_reference(source_reference)?;
    let target_canonical = canonicalize_reference(target_reference)?;

    let source = store
        .resolve_reference(&source_canonical)?
        .ok_or_else(|| ImageTaggingError::SourceNotFound(source_canonical.clone()))?;

    store.put_reference(
        authority,
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
    let source = match store.resolve_reference(&plan.source_reference) {
        Ok(Some(source)) => source,
        Ok(None) => {
            permit
                .finish(false)
                .map_err(|error| ImageTaggingError::Authorization(error.to_string()))?;
            return Err(ImageTaggingError::SourceNotFound(
                plan.source_reference.clone(),
            ));
        }
        Err(error) => {
            permit
                .finish(false)
                .map_err(|finish| ImageTaggingError::Authorization(finish.to_string()))?;
            return Err(error.into());
        }
    };
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
    let authority = permit.mutation_authority();
    match store.put_reference(
        &authority,
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
    use super::{
        canonicalize_reference, execute_image_tag_authorized, normalize_selector,
        prepare_image_tag, resolve_reference, tag_image, ImageSelector,
    };
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
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                "registry-1.docker.io/library/alpine:latest",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "application/vnd.oci.image.manifest.v1+json",
                "{\"schemaVersion\":2}",
            )
            .expect("seed source image");

        tag_image(
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
            "alpine",
            "ghcr.io/acme/alpine:stable",
        )
        .expect("tag image");

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

        let err = tag_image(
            &store,
            &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
            "missing:latest",
            "acme/new:latest",
        )
        .expect_err("tagging should fail");

        assert!(err.to_string().contains("source image not found"));
    }

    #[test]
    fn resolves_full_digest_forms_and_unique_abbreviations_without_registry_parsing() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path()).unwrap();
        let digest = format!("sha256:abc123456789{}", "d".repeat(52));
        store
            .put_reference(
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                "registry.example/team/app:latest",
                &digest,
                "test",
                "{}",
            )
            .unwrap();

        for selector in [
            "abc1",
            "ABC1",
            digest.strip_prefix("sha256:").unwrap(),
            &digest.strip_prefix("sha256:").unwrap().to_ascii_uppercase(),
            digest.as_str(),
            &format!(
                "sha256:{}",
                digest.strip_prefix("sha256:").unwrap().to_ascii_uppercase()
            ),
        ] {
            assert_eq!(
                resolve_reference(&store, selector).unwrap().unwrap().digest,
                digest
            );
        }
        assert!(matches!(
            normalize_selector("abcdefabcdef"),
            Ok(ImageSelector::IdPrefix(_))
        ));
    }

    #[test]
    fn rejects_ambiguous_id_prefixes_and_keeps_missing_ids_local_only() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path()).unwrap();
        for (name, suffix) in [("one", "1"), ("two", "2")] {
            store
                .put_reference(
                    &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                    &format!("registry.example/team/{name}:latest"),
                    &format!("sha256:abcdefabcdef{suffix}{}", suffix.repeat(51)),
                    "test",
                    "{}",
                )
                .unwrap();
        }
        assert!(resolve_reference(&store, "abcdefabcdef")
            .unwrap_err()
            .to_string()
            .contains("multiple images match prefix"));
        assert!(resolve_reference(&store, "deadbeefdead").unwrap().is_none());
    }
    #[test]
    fn authorized_named_tag_rejects_source_retarget_without_creating_target() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path()).unwrap();
        let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();
        let source = "registry.example/team/source:latest";
        let target = "registry.example/team/target:latest";
        let digest_a = format!("sha256:{}", "a".repeat(64));
        let digest_b = format!("sha256:{}", "b".repeat(64));
        store
            .put_reference(&authority, source, &digest_a, "test", "{\"version\":1}")
            .unwrap();
        let plan = prepare_image_tag(&store, source, target).unwrap();
        let auth = crate::authorization::surface::SurfaceAuthorization::compatibility();
        let origin = crate::authorization::RequestOrigin::cli_current().unwrap();
        let permit = auth.authorize_image_tag_plan(&origin, &plan).unwrap();
        store
            .put_reference(&authority, source, &digest_b, "test", "{\"version\":2}")
            .unwrap();
        assert!(execute_image_tag_authorized(&store, plan, permit)
            .unwrap_err()
            .to_string()
            .contains("source changed after authorization"));
        assert!(store.resolve_reference(target).unwrap().is_none());
    }

    #[test]
    fn authorized_named_tag_rejects_removed_source_without_creating_target() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path()).unwrap();
        let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();
        let source = "registry.example/team/source:latest";
        let target = "registry.example/team/target:latest";
        let digest = format!("sha256:{}", "a".repeat(64));
        store
            .put_reference(&authority, source, &digest, "test", "{\"version\":1}")
            .unwrap();
        let plan = prepare_image_tag(&store, source, target).unwrap();
        let auth = crate::authorization::surface::SurfaceAuthorization::compatibility();
        let origin = crate::authorization::RequestOrigin::cli_current().unwrap();
        let permit = auth.authorize_image_tag_plan(&origin, &plan).unwrap();
        assert_eq!(store.prune_references(&authority).unwrap(), 1);
        assert!(matches!(
            execute_image_tag_authorized(&store, plan, permit),
            Err(super::ImageTaggingError::SourceNotFound(_))
        ));
        assert!(store.resolve_reference(target).unwrap().is_none());
    }

    #[test]
    fn authorized_id_tag_stays_pinned_to_selected_full_digest() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path()).unwrap();
        let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();
        let digest_a = format!("sha256:abcde{}", "1".repeat(59));
        let digest_b = format!("sha256:abcde{}", "2".repeat(59));
        let target = "registry.example/team/target:latest";
        store
            .put_reference(
                &authority,
                "registry.example/team/a:latest",
                &digest_a,
                "test",
                "{\"version\":1}",
            )
            .unwrap();
        let plan = prepare_image_tag(&store, "ABCDE", target).unwrap();
        let auth = crate::authorization::surface::SurfaceAuthorization::compatibility();
        let origin = crate::authorization::RequestOrigin::cli_current().unwrap();
        let permit = auth.authorize_image_tag_plan(&origin, &plan).unwrap();
        store
            .put_reference(
                &authority,
                "registry.example/team/b:latest",
                &digest_b,
                "test",
                "{\"version\":2}",
            )
            .unwrap();
        execute_image_tag_authorized(&store, plan, permit).unwrap();
        assert_eq!(
            store.resolve_reference(target).unwrap().unwrap().digest,
            digest_a
        );
    }
}
