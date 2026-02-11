use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const IMAGE_INDEX_TREE: &str = "image_index";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageRecord {
    pub reference: String,
    pub digest: String,
    pub manifest_media_type: String,
    pub manifest_json: String,
    pub created_at_unix: u64,
}

#[derive(Debug, Error)]
pub enum ImageStoreError {
    #[error("failed to open image store: {0}")]
    Open(#[from] sled::Error),
    #[error("failed to encode image record: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("failed to decode image record: {0}")]
    Decode(#[source] serde_json::Error),
}

pub struct LocalImageStore {
    db: sled::Db,
}

impl LocalImageStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ImageStoreError> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    pub fn put_reference(
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
        tree.insert(reference.as_bytes(), encoded)?;
        tree.flush()?;
        Ok(())
    }

    pub fn resolve_reference(&self, reference: &str) -> Result<Option<ImageRecord>, ImageStoreError> {
        let tree = self.db.open_tree(IMAGE_INDEX_TREE)?;

        let maybe_record = tree.get(reference.as_bytes())?;
        maybe_record
            .map(|bytes| {
                serde_json::from_slice::<ImageRecord>(&bytes)
                    .map_err(ImageStoreError::Decode)
            })
            .transpose()
    }

    pub fn remove_reference(&self, reference: &str) -> Result<bool, ImageStoreError> {
        let tree = self.db.open_tree(IMAGE_INDEX_TREE)?;
        let removed = tree.remove(reference.as_bytes())?.is_some();
        tree.flush()?;
        Ok(removed)
    }

    pub fn list_references(&self) -> Result<Vec<ImageRecord>, ImageStoreError> {
        let tree = self.db.open_tree(IMAGE_INDEX_TREE)?;
        let mut out = Vec::new();

        for item in &tree {
            let (_, value) = item?;
            let decoded = serde_json::from_slice::<ImageRecord>(&value)
                .map_err(ImageStoreError::Decode)?;
            out.push(decoded);
        }

        out.sort_by(|a, b| a.reference.cmp(&b.reference));
        Ok(out)
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
    use super::LocalImageStore;

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
}
