use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::transaction::Transactional;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const IMAGE_INDEX_TREE: &str = "image_index";
const IMAGE_DIGEST_TREE: &str = "image_digest_index";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageRecord {
    pub reference: String,
    pub digest: String,
    pub manifest_media_type: String,
    pub manifest_json: String,
    pub created_at_unix: u64,
}

#[derive(Clone, Debug)]
pub struct ImageReferenceWritePlan {
    canonical_reference: String,
    digest: String,
    manifest_media_type: String,
    manifest_json: String,
    plan_digest: [u8; 32],
}

impl ImageReferenceWritePlan {
    pub fn canonical_reference(&self) -> &str {
        &self.canonical_reference
    }
    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }
    pub fn generation(&self) -> u64 {
        1
    }
}

#[derive(Debug, Error)]
pub enum ImageStoreError {
    #[error("failed to open image store: {0}")]
    Open(#[from] sled::Error),
    #[error("failed to encode image record: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("failed to decode image record: {0}")]
    Decode(#[source] serde_json::Error),
    #[error("image authorization binding failed: {0}")]
    Authorization(String),
}

#[derive(Clone)]
pub struct LocalImageStore {
    db: sled::Db,
}

impl LocalImageStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ImageStoreError> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    pub(crate) fn put_reference(
        &self,
        reference: &str,
        digest: &str,
        manifest_media_type: &str,
        manifest_json: &str,
    ) -> Result<(), ImageStoreError> {
        let tree = self.db.open_tree(IMAGE_INDEX_TREE)?;
        let record = ImageRecord {
            reference: reference.to_string(),
            digest: digest.to_string(),
            manifest_media_type: manifest_media_type.to_string(),
            manifest_json: manifest_json.to_string(),
            created_at_unix: now_unix(),
        };

        let encoded = serde_json::to_vec(&record)?;
        let digest_tree = self.db.open_tree(IMAGE_DIGEST_TREE)?;
        let digest_encoded = serde_json::to_vec(&record)?;
        (&tree, &digest_tree)
            .transaction(|(references, digests)| {
                references.insert(reference.as_bytes(), encoded.as_slice())?;
                digests.insert(digest.as_bytes(), digest_encoded.as_slice())?;
                Ok::<_, sled::transaction::ConflictableTransactionError<()>>(())
            })
            .map_err(|error| match error {
                sled::transaction::TransactionError::Abort(()) => {
                    ImageStoreError::Authorization("image publication aborted".into())
                }
                sled::transaction::TransactionError::Storage(error) => ImageStoreError::Open(error),
            })?;
        tree.flush()?;
        digest_tree.flush()?;
        Ok(())
    }

    pub fn prepare_reference_write(
        &self,
        reference: &str,
        digest: &str,
        manifest_media_type: &str,
        manifest_json: &str,
    ) -> Result<ImageReferenceWritePlan, ImageStoreError> {
        let canonical_reference = crate::image_tagging::canonicalize_reference(reference)
            .map_err(|error| ImageStoreError::Authorization(error.to_string()))?;
        let manifest = crate::image_manifest::parse_image_manifest(manifest_json)
            .map_err(|error| ImageStoreError::Authorization(error.to_string()))?;
        if manifest.config.digest != digest || manifest.media_type != manifest_media_type {
            return Err(ImageStoreError::Authorization(
                "reference metadata does not match parsed manifest".to_string(),
            ));
        }
        let mut hash = Sha256::new();
        hash.update(b"ferrocrate/image-reference-write-plan/v1");
        for value in [
            canonical_reference.as_str(),
            digest,
            manifest_media_type,
            manifest_json,
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        Ok(ImageReferenceWritePlan {
            canonical_reference,
            digest: digest.to_string(),
            manifest_media_type: manifest_media_type.to_string(),
            manifest_json: manifest_json.to_string(),
            plan_digest: hash.finalize().into(),
        })
    }

    pub fn put_reference_authorized(
        &self,
        plan: ImageReferenceWritePlan,
        permit: crate::authorization::surface::SurfacePermit,
    ) -> Result<(), ImageStoreError> {
        crate::authorization::surface::SurfaceAuthorization::validate_execution(
            &permit,
            crate::authorization::Action::ImageReferenceWrite,
            crate::authorization::ResourceKind::Image,
            plan.canonical_reference(),
            plan.generation(),
        )
        .map_err(|error| ImageStoreError::Authorization(error.to_string()))?;
        if permit.proof().canonical().operation_plan_digest() != Some(&plan.plan_digest()) {
            permit
                .finish(false)
                .map_err(|error| ImageStoreError::Authorization(error.to_string()))?;
            return Err(ImageStoreError::Authorization(
                "reference write plan does not match proof".to_string(),
            ));
        }
        match self.put_reference(
            &plan.canonical_reference,
            &plan.digest,
            &plan.manifest_media_type,
            &plan.manifest_json,
        ) {
            Ok(()) => permit
                .finish(true)
                .map_err(|error| ImageStoreError::Authorization(error.to_string())),
            Err(error) => {
                permit
                    .finish_unknown()
                    .map_err(|finish| ImageStoreError::Authorization(finish.to_string()))?;
                Err(error)
            }
        }
    }

    pub fn resolve_reference(
        &self,
        reference: &str,
    ) -> Result<Option<ImageRecord>, ImageStoreError> {
        let tree = self.db.open_tree(IMAGE_INDEX_TREE)?;

        let maybe_record = tree.get(reference.as_bytes())?;
        let exact = maybe_record
            .map(|bytes| {
                serde_json::from_slice::<ImageRecord>(&bytes).map_err(ImageStoreError::Decode)
            })
            .transpose()?;
        if exact.is_some() {
            return Ok(exact);
        }
        let requested_digest = reference.rsplit_once('@').map(|(_, digest)| digest);
        if let Some(digest) = requested_digest {
            let digest_tree = self.db.open_tree(IMAGE_DIGEST_TREE)?;
            if let Some(bytes) = digest_tree.get(digest.as_bytes())? {
                return serde_json::from_slice::<ImageRecord>(&bytes)
                    .map(Some)
                    .map_err(ImageStoreError::Decode);
            }
        }
        Ok(None)
    }

    pub(crate) fn remove_reference(&self, reference: &str) -> Result<bool, ImageStoreError> {
        let tree = self.db.open_tree(IMAGE_INDEX_TREE)?;
        let removed = tree.remove(reference.as_bytes())?.is_some();
        tree.flush()?;
        Ok(removed)
    }

    pub fn remove_reference_authorized(
        &self,
        reference: &str,
        digest: &str,
        permit: crate::authorization::surface::SurfacePermit,
    ) -> Result<bool, ImageStoreError> {
        crate::authorization::surface::SurfaceAuthorization::validate_execution(
            &permit,
            crate::authorization::Action::ImageDelete,
            crate::authorization::ResourceKind::Image,
            reference,
            1,
        )
        .map_err(|error| ImageStoreError::Authorization(error.to_string()))?;
        if permit.proof().canonical().image_digest() != Some(digest) {
            return Err(ImageStoreError::Authorization(
                "image digest does not match executor".to_string(),
            ));
        }
        match self.remove_reference(reference) {
            Ok(removed) => {
                permit
                    .finish(true)
                    .map_err(|error| ImageStoreError::Authorization(error.to_string()))?;
                Ok(removed)
            }
            Err(error) => {
                permit
                    .finish(false)
                    .map_err(|finish| ImageStoreError::Authorization(finish.to_string()))?;
                Err(error)
            }
        }
    }

    pub fn list_references(&self) -> Result<Vec<ImageRecord>, ImageStoreError> {
        let tree = self.db.open_tree(IMAGE_INDEX_TREE)?;
        let mut out = Vec::new();

        for item in &tree {
            let (_, value) = item?;
            let decoded =
                serde_json::from_slice::<ImageRecord>(&value).map_err(ImageStoreError::Decode)?;
            out.push(decoded);
        }

        out.sort_by(|a, b| a.reference.cmp(&b.reference));
        Ok(out)
    }

    pub(crate) fn prune_references(&self) -> Result<usize, ImageStoreError> {
        let tree = self.db.open_tree(IMAGE_INDEX_TREE)?;
        let keys: Vec<Vec<u8>> = tree
            .iter()
            .keys()
            .map(|key| key.map(|val| val.to_vec()))
            .collect::<Result<_, _>>()?;
        let mut removed = 0;
        for key in keys {
            if tree.remove(key)?.is_some() {
                removed += 1;
            }
        }
        tree.flush()?;
        let digest_tree = self.db.open_tree(IMAGE_DIGEST_TREE)?;
        digest_tree.clear()?;
        digest_tree.flush()?;
        Ok(removed)
    }

    /// Consume one independently authorized permit for every reference that
    /// will be removed. A concurrent inventory change fails closed.
    pub fn prune_references_authorized(
        &self,
        permits: Vec<crate::authorization::surface::SurfacePermit>,
    ) -> Result<usize, ImageStoreError> {
        let records = self.list_references()?;
        if records.len() != permits.len() {
            return Err(ImageStoreError::Authorization(
                "image prune authorization set does not match current inventory".to_string(),
            ));
        }
        for (record, permit) in records.iter().zip(&permits) {
            crate::authorization::surface::SurfaceAuthorization::validate_execution(
                permit,
                crate::authorization::Action::ImageDelete,
                crate::authorization::ResourceKind::Image,
                &record.reference,
                1,
            )
            .map_err(|error| ImageStoreError::Authorization(error.to_string()))?;
            if permit.proof().canonical().image_digest() != Some(record.digest.as_str()) {
                return Err(ImageStoreError::Authorization(
                    "image prune digest does not match executor".to_string(),
                ));
            }
        }
        match self.prune_references() {
            Ok(removed) => {
                for permit in permits {
                    permit
                        .finish(true)
                        .map_err(|error| ImageStoreError::Authorization(error.to_string()))?;
                }
                Ok(removed)
            }
            Err(error) => {
                for permit in permits {
                    permit
                        .finish_unknown()
                        .map_err(|finish| ImageStoreError::Authorization(finish.to_string()))?;
                }
                Err(error)
            }
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{ImageStoreError, LocalImageStore};

    #[test]
    fn reference_write_preparation_is_side_effect_free_and_checks_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path()).unwrap();
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{}","size":2}},"layers":[]}}"#,
            "a".repeat(64)
        );
        let plan = store
            .prepare_reference_write(
                "local/app:test",
                &format!("sha256:{}", "a".repeat(64)),
                "application/vnd.oci.image.manifest.v1+json",
                &manifest,
            )
            .unwrap();
        assert!(store.list_references().unwrap().is_empty());
        assert!(plan.canonical_reference().ends_with("/local/app:test"));
        let error = store
            .prepare_reference_write(
                "local/app:test",
                &format!("sha256:{}", "b".repeat(64)),
                "application/vnd.oci.image.manifest.v1+json",
                &manifest,
            )
            .unwrap_err();
        assert!(matches!(error, ImageStoreError::Authorization(_)));
    }

    #[test]
    fn stores_and_resolves_reference() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open store");

        store
            .put_reference(
                "ghcr.io/acme/app:latest",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "application/vnd.oci.image.manifest.v1+json",
                "{\"schemaVersion\":2}",
            )
            .expect("store record");

        let resolved = store
            .resolve_reference("ghcr.io/acme/app:latest")
            .expect("resolve should succeed")
            .expect("record exists");

        assert_eq!(resolved.reference, "ghcr.io/acme/app:latest");
        assert_eq!(
            resolved.digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn digest_qualified_resolution_survives_tag_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path()).unwrap();
        let old = format!("sha256:{}", "a".repeat(64));
        let new = format!("sha256:{}", "b".repeat(64));
        store
            .put_reference("repo/app:latest", &old, "test", "{}")
            .unwrap();
        store
            .put_reference("repo/app:latest", &new, "test", "{}")
            .unwrap();
        assert_eq!(
            store
                .resolve_reference(&format!("repo/app@{old}"))
                .unwrap()
                .unwrap()
                .digest,
            old
        );
        assert_eq!(
            store
                .resolve_reference("repo/app:latest")
                .unwrap()
                .unwrap()
                .digest,
            new
        );
    }

    #[test]
    fn lists_and_removes_references() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open store");

        store
            .put_reference(
                "docker.io/library/alpine:latest",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "application/vnd.oci.image.manifest.v1+json",
                "{\"schemaVersion\":2}",
            )
            .expect("store record");

        store
            .put_reference(
                "ghcr.io/acme/app:v1",
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "application/vnd.oci.image.manifest.v1+json",
                "{\"schemaVersion\":2}",
            )
            .expect("store record");

        let listed = store.list_references().expect("list references");
        assert_eq!(listed.len(), 2);

        let removed = store
            .remove_reference("docker.io/library/alpine:latest")
            .expect("remove reference");
        assert!(removed);

        let listed_after = store.list_references().expect("list references");
        assert_eq!(listed_after.len(), 1);
        assert_eq!(listed_after[0].reference, "ghcr.io/acme/app:v1");
    }

    #[test]
    fn prunes_all_references() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open store");

        store
            .put_reference(
                "docker.io/library/alpine:latest",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "application/vnd.oci.image.manifest.v1+json",
                "{\"schemaVersion\":2}",
            )
            .expect("store record");

        store
            .put_reference(
                "ghcr.io/acme/app:v1",
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "application/vnd.oci.image.manifest.v1+json",
                "{\"schemaVersion\":2}",
            )
            .expect("store record");

        let removed = store.prune_references().expect("prune");
        assert_eq!(removed, 2);
        let listed = store.list_references().expect("list");
        assert!(listed.is_empty());
    }
}
