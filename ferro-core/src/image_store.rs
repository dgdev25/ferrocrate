use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const IMAGE_SQLITE_SUFFIX: &str = "sqlite";

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageDeletePlan {
    digest: String,
    references: Vec<String>,
}

impl ImageDeletePlan {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn references(&self) -> &[String] {
        &self.references
    }
}

#[derive(Debug, Error)]
pub enum ImageStoreError {
    #[error("failed to open image store: {0}")]
    Open(#[from] rusqlite::Error),
    #[error("failed to lock image store: {0}")]
    Lock(String),
    #[error("legacy Sled image store detected; the Sled importer was removed. See docs/architecture/legacy-sled-importers.md")]
    LegacyMigrationRequired,
    #[error("image store io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to encode image record: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("failed to decode image record: {0}")]
    Decode(#[source] serde_json::Error),
    #[error("image authorization binding failed: {0}")]
    Authorization(String),
    #[error("multiple images match prefix: {0}")]
    AmbiguousIdPrefix(String),
    #[error("conflict: unable to delete {0} because it has multiple references; use force")]
    DeleteConflict(String),
    #[error("image not found: {0}")]
    DeleteNotFound(String),
    #[error("image delete inventory changed after authorization")]
    DeleteInventoryChanged,
}

#[derive(Clone)]
pub struct LocalImageStore {
    db: Arc<Mutex<Connection>>,
}

fn image_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ImageRecord> {
    Ok(ImageRecord {
        reference: row.get(0)?,
        digest: row.get(1)?,
        manifest_media_type: row.get(2)?,
        manifest_json: row.get(3)?,
        created_at_unix: (row.get::<_, i64>(4)?).max(0) as u64,
    })
}

impl LocalImageStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ImageStoreError> {
        let legacy_path = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&legacy_path)?;
        let db_path = PathBuf::from(format!("{}.{}", legacy_path.display(), IMAGE_SQLITE_SUFFIX));
        if !db_path.exists() && legacy_path.join("conf").exists() {
            return Err(ImageStoreError::LegacyMigrationRequired);
        }
        let db = Connection::open(db_path)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS image_references (
                reference TEXT PRIMARY KEY NOT NULL,
                digest TEXT NOT NULL,
                manifest_media_type TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS image_digests (
                digest TEXT PRIMARY KEY NOT NULL,
                reference TEXT NOT NULL,
                manifest_media_type TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL
            );",
        )?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
        })
    }

    pub(crate) fn put_reference(
        &self,
        _authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
        reference: &str,
        digest: &str,
        manifest_media_type: &str,
        manifest_json: &str,
    ) -> Result<(), ImageStoreError> {
        let record = ImageRecord {
            reference: reference.to_string(),
            digest: digest.to_string(),
            manifest_media_type: manifest_media_type.to_string(),
            manifest_json: manifest_json.to_string(),
            created_at_unix: now_unix(),
        };

        let mut db = self
            .db
            .lock()
            .map_err(|error| ImageStoreError::Lock(error.to_string()))?;
        let transaction = db.transaction()?;
        transaction.execute(
            "INSERT INTO image_references
             (reference, digest, manifest_media_type, manifest_json, created_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(reference) DO UPDATE SET
               digest = excluded.digest,
               manifest_media_type = excluded.manifest_media_type,
               manifest_json = excluded.manifest_json,
               created_at_unix = excluded.created_at_unix",
            params![
                record.reference,
                record.digest,
                record.manifest_media_type,
                record.manifest_json,
                record.created_at_unix as i64
            ],
        )?;
        transaction.execute(
            "INSERT OR REPLACE INTO image_digests
             (digest, reference, manifest_media_type, manifest_json, created_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                record.digest,
                record.reference,
                record.manifest_media_type,
                record.manifest_json,
                record.created_at_unix as i64
            ],
        )?;
        transaction.commit()?;
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
        let authority = permit.mutation_authority();
        match self.put_reference(
            &authority,
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
        let db = self
            .db
            .lock()
            .map_err(|error| ImageStoreError::Lock(error.to_string()))?;
        match db.query_row(
            "SELECT reference, digest, manifest_media_type, manifest_json, created_at_unix
             FROM image_references WHERE reference = ?1",
            params![reference],
            image_record_from_row,
        ) {
            Ok(record) => return Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => {}
            Err(error) => return Err(error.into()),
        }
        let requested_digest = reference
            .strip_prefix("sha256:")
            .map(|_| reference)
            .or_else(|| reference.rsplit_once('@').map(|(_, digest)| digest));
        if let Some(digest) = requested_digest {
            match db.query_row(
                "SELECT reference, digest, manifest_media_type, manifest_json, created_at_unix
                 FROM image_digests WHERE digest = ?1",
                params![digest],
                image_record_from_row,
            ) {
                Ok(mut record) => {
                    if reference.contains('@') {
                        record.reference = reference.to_string();
                    }
                    return Ok(Some(record));
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(None)
    }

    pub fn resolve_id_prefix(&self, prefix: &str) -> Result<Option<ImageRecord>, ImageStoreError> {
        let db = self
            .db
            .lock()
            .map_err(|error| ImageStoreError::Lock(error.to_string()))?;
        let pattern = format!("sha256:{}%", prefix.to_ascii_lowercase());
        let mut statement = db.prepare(
            "SELECT reference, digest, manifest_media_type, manifest_json, created_at_unix
             FROM image_digests WHERE lower(digest) LIKE ?1 ORDER BY digest LIMIT 2",
        )?;
        let records = statement
            .query_map(params![pattern], image_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        match records.as_slice() {
            [] => Ok(None),
            [record] => Ok(Some(record.clone())),
            _ => Err(ImageStoreError::AmbiguousIdPrefix(prefix.to_string())),
        }
    }

    fn remove_reference_if_digest(
        &self,
        reference: &str,
        digest: &str,
    ) -> Result<bool, ImageStoreError> {
        let db = self
            .db
            .lock()
            .map_err(|error| ImageStoreError::Lock(error.to_string()))?;
        Ok(db.execute(
            "DELETE FROM image_references WHERE reference = ?1 AND digest = ?2",
            params![reference, digest],
        )? > 0)
    }

    pub fn prepare_digest_delete(
        &self,
        digest: &str,
        force: bool,
    ) -> Result<ImageDeletePlan, ImageStoreError> {
        let db = self
            .db
            .lock()
            .map_err(|error| ImageStoreError::Lock(error.to_string()))?;
        let mut statement = db.prepare(
            "SELECT reference FROM image_references WHERE digest = ?1 ORDER BY reference",
        )?;
        let references = statement
            .query_map(params![digest], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        if references.is_empty() {
            return Err(ImageStoreError::DeleteNotFound(digest.to_string()));
        }
        if !force && references.len() != 1 {
            return Err(ImageStoreError::DeleteConflict(digest.to_string()));
        }
        Ok(ImageDeletePlan {
            digest: digest.to_string(),
            references,
        })
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
        match self.remove_reference_if_digest(reference, digest) {
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

    pub fn execute_digest_delete_authorized(
        &self,
        plan: ImageDeletePlan,
        permits: Vec<crate::authorization::surface::SurfacePermit>,
    ) -> Result<bool, ImageStoreError> {
        if plan.references.is_empty() {
            finish_image_delete_permits(permits, false)?;
            return Err(ImageStoreError::DeleteNotFound(plan.digest));
        }
        if plan.references.len() != permits.len() {
            finish_image_delete_permits(permits, false)?;
            return Err(ImageStoreError::Authorization(
                "image delete authorization set does not match planned inventory".to_string(),
            ));
        }
        let validation = plan.references.iter().zip(&permits).try_for_each(
            |(reference, permit)| -> Result<(), ImageStoreError> {
                crate::authorization::surface::SurfaceAuthorization::validate_execution(
                    permit,
                    crate::authorization::Action::ImageDelete,
                    crate::authorization::ResourceKind::Image,
                    reference,
                    1,
                )
                .map_err(|error| ImageStoreError::Authorization(error.to_string()))?;
                if permit.proof().canonical().image_digest() != Some(plan.digest.as_str()) {
                    return Err(ImageStoreError::Authorization(
                        "image delete digest does not match executor".to_string(),
                    ));
                }
                Ok(())
            },
        );
        if let Err(error) = validation {
            finish_image_delete_permits(permits, false)?;
            return Err(error);
        }
        let result = (|| {
            let mut db = self
                .db
                .lock()
                .map_err(|error| ImageStoreError::Lock(error.to_string()))?;
            let transaction = db.transaction()?;
            let current = {
                let mut statement = transaction.prepare(
                    "SELECT reference FROM image_references WHERE digest = ?1 ORDER BY reference",
                )?;
                let rows = statement
                    .query_map(params![plan.digest], |row| row.get(0))?
                    .collect::<Result<Vec<String>, _>>()?;
                rows
            };
            if current != plan.references {
                return Err(ImageStoreError::DeleteInventoryChanged);
            }
            let references = transaction.execute(
                "DELETE FROM image_references WHERE digest = ?1",
                params![plan.digest],
            )?;
            let records = transaction.execute(
                "DELETE FROM image_digests WHERE digest = ?1",
                params![plan.digest],
            )?;
            transaction.commit()?;
            Ok(references > 0 || records > 0)
        })();
        match result {
            Ok(removed) => {
                finish_image_delete_permits(permits, true)?;
                Ok(removed)
            }
            Err(error) => {
                finish_image_delete_permits(permits, false)?;
                Err(error)
            }
        }
    }

    pub fn list_references(&self) -> Result<Vec<ImageRecord>, ImageStoreError> {
        let db = self
            .db
            .lock()
            .map_err(|error| ImageStoreError::Lock(error.to_string()))?;
        let mut statement = db.prepare(
            "SELECT reference, digest, manifest_media_type, manifest_json, created_at_unix
             FROM image_references ORDER BY reference",
        )?;
        let mut out = Vec::new();
        for item in statement.query_map([], image_record_from_row)? {
            out.push(item?);
        }
        Ok(out)
    }

    #[cfg(test)]
    pub(crate) fn prune_references(
        &self,
        _authority: &crate::authorization::surface::SurfaceMutationAuthority<'_>,
    ) -> Result<usize, ImageStoreError> {
        let mut db = self
            .db
            .lock()
            .map_err(|error| ImageStoreError::Lock(error.to_string()))?;
        let transaction = db.transaction()?;
        let removed = transaction.execute("DELETE FROM image_references", [])?;
        transaction.execute("DELETE FROM image_digests", [])?;
        transaction.commit()?;
        Ok(removed)
    }

    /// Consume one independently authorized permit for every reference that
    /// will be removed. A concurrent inventory change fails closed.
    pub fn prune_references_authorized(
        &self,
        permits: Vec<crate::authorization::surface::SurfacePermit>,
        selected_references: &[String],
    ) -> Result<usize, ImageStoreError> {
        let records = self.list_references()?;
        if selected_references.len() != permits.len() {
            return Err(ImageStoreError::Authorization(
                "image prune authorization set does not match selected inventory".to_string(),
            ));
        }
        let selected = selected_references
            .iter()
            .zip(&permits)
            .map(|(reference, permit)| {
                records
                    .iter()
                    .find(|record| &record.reference == reference)
                    .ok_or_else(|| {
                        ImageStoreError::Authorization(
                            "image prune selection changed during authorization".to_string(),
                        )
                    })
                    .and_then(|record| {
                        crate::authorization::surface::SurfaceAuthorization::validate_execution(
                            permit,
                            crate::authorization::Action::ImageDelete,
                            crate::authorization::ResourceKind::Image,
                            &record.reference,
                            1,
                        )
                        .map_err(|error| ImageStoreError::Authorization(error.to_string()))?;
                        if permit.proof().canonical().image_digest() != Some(record.digest.as_str())
                        {
                            return Err(ImageStoreError::Authorization(
                                "image prune digest does not match executor".to_string(),
                            ));
                        }
                        Ok(record.reference.clone())
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if selected.is_empty() {
            return Ok(0);
        }
        let result = (|| {
            let mut db = self
                .db
                .lock()
                .map_err(|error| ImageStoreError::Lock(error.to_string()))?;
            let transaction = db.transaction()?;
            let mut removed = 0;
            for reference in &selected {
                removed += transaction.execute(
                    "DELETE FROM image_references WHERE reference = ?1",
                    params![reference],
                )?;
            }
            transaction.commit()?;
            Ok(removed)
        })();
        match result {
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

fn finish_image_delete_permits(
    permits: Vec<crate::authorization::surface::SurfacePermit>,
    succeeded: bool,
) -> Result<(), ImageStoreError> {
    let mut first_error = None;
    for permit in permits {
        if let Err(error) = permit.finish(succeeded) {
            first_error.get_or_insert_with(|| ImageStoreError::Authorization(error.to_string()));
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{ImageDeletePlan, ImageStoreError, LocalImageStore};
    use rusqlite::params;

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
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
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
            .put_reference(
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                "repo/app:latest",
                &old,
                "test",
                "{}",
            )
            .unwrap();
        store
            .put_reference(
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                "repo/app:latest",
                &new,
                "test",
                "{}",
            )
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
    fn repository_digest_lookup_preserves_the_requested_repository() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path()).unwrap();
        let digest = format!("sha256:{}", "d".repeat(64));
        store
            .put_reference(
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                "registry.one/team/app:latest",
                &digest,
                "test",
                "{}",
            )
            .unwrap();
        let requested = format!("registry.two/other/app@{digest}");
        let record = store.resolve_reference(&requested).unwrap().unwrap();
        assert_eq!(record.reference, requested);
        assert_eq!(record.digest, digest);
    }

    #[test]
    fn lists_and_removes_references() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open store");

        store
            .put_reference(
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                "docker.io/library/alpine:latest",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "application/vnd.oci.image.manifest.v1+json",
                "{\"schemaVersion\":2}",
            )
            .expect("store record");

        store
            .put_reference(
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                "ghcr.io/acme/app:v1",
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "application/vnd.oci.image.manifest.v1+json",
                "{\"schemaVersion\":2}",
            )
            .expect("store record");

        let listed = store.list_references().expect("list references");
        assert_eq!(listed.len(), 2);

        let removed = store
            .remove_reference_if_digest(
                "docker.io/library/alpine:latest",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
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
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                "docker.io/library/alpine:latest",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "application/vnd.oci.image.manifest.v1+json",
                "{\"schemaVersion\":2}",
            )
            .expect("store record");

        store
            .put_reference(
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                "ghcr.io/acme/app:v1",
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "application/vnd.oci.image.manifest.v1+json",
                "{\"schemaVersion\":2}",
            )
            .expect("store record");

        let removed = store
            .prune_references(&crate::authorization::surface::SurfaceMutationAuthority::for_test())
            .expect("prune");
        assert_eq!(removed, 2);
        let listed = store.list_references().expect("list");
        assert!(listed.is_empty());
    }

    #[test]
    fn digest_delete_requires_force_authorizes_inventory_and_rejects_drift() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path()).unwrap();
        let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();
        let digest = format!("sha256:{}", "d".repeat(64));
        for reference in ["registry.example/acme/app:one", "registry.example/acme/app:two"] {
            store
                .put_reference(&authority, reference, &digest, "test", "{}")
                .unwrap();
        }
        assert!(matches!(
            store.prepare_digest_delete(&digest, false),
            Err(ImageStoreError::DeleteConflict(_))
        ));

        let plan = store.prepare_digest_delete(&digest, true).unwrap();
        assert_eq!(
            plan.references(),
            [
                "registry.example/acme/app:one".to_string(),
                "registry.example/acme/app:two".to_string()
            ]
        );
        let auth = crate::authorization::surface::SurfaceAuthorization::compatibility();
        let origin = crate::authorization::RequestOrigin::cli_current().unwrap();
        let wrong_permits = plan
            .references()
            .iter()
            .enumerate()
            .map(|(index, reference)| {
                auth.authorize_image_binding(
                    &origin,
                    crate::authorization::Action::ImageDelete,
                    if index == 1 { "registry.example/acme/not-authorized:latest" } else { reference },
                    &digest,
                    1,
                )
                .unwrap()
            })
            .collect();
        assert!(matches!(
            store.execute_digest_delete_authorized(plan, wrong_permits),
            Err(ImageStoreError::Authorization(_))
        ));
        assert_eq!(store.list_references().unwrap().len(), 2);

        let plan = store.prepare_digest_delete(&digest, true).unwrap();
        let permits = plan
            .references()
            .iter()
            .map(|reference| {
                auth.authorize_image_binding(
                    &origin,
                    crate::authorization::Action::ImageDelete,
                    reference,
                    &digest,
                    1,
                )
                .unwrap()
            })
            .collect();
        store
            .put_reference(
                &authority,
                "registry.example/acme/app:concurrent",
                &digest,
                "test",
                "{}",
            )
            .unwrap();
        assert!(matches!(
            store.execute_digest_delete_authorized(plan, permits),
            Err(ImageStoreError::DeleteInventoryChanged)
        ));
        assert_eq!(store.list_references().unwrap().len(), 3);

        let plan = store.prepare_digest_delete(&digest, true).unwrap();
        let permits = plan
            .references()
            .iter()
            .map(|reference| {
                auth.authorize_image_binding(
                    &origin,
                    crate::authorization::Action::ImageDelete,
                    reference,
                    &digest,
                    1,
                )
                .unwrap()
            })
            .collect();
        assert!(store
            .execute_digest_delete_authorized(plan, permits)
            .unwrap());
        assert!(store.list_references().unwrap().is_empty());
    }

    #[test]
    fn digest_delete_rejects_zero_reference_planning_and_execution() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalImageStore::open(temp.path()).unwrap();
        let digest = format!("sha256:{}", "e".repeat(64));
        {
            let db = store.db.lock().unwrap();
            db.execute(
                "INSERT INTO image_digests (digest, reference, manifest_media_type, manifest_json, created_at_unix) VALUES (?1, 'detached', 'test', '{}', 0)",
                params![digest],
            )
            .unwrap();
        }
        for force in [false, true] {
            assert!(matches!(
                store.prepare_digest_delete(&digest, force),
                Err(ImageStoreError::DeleteNotFound(found)) if found == digest
            ));
        }
        let empty_plan = ImageDeletePlan { digest: digest.clone(), references: Vec::new() };
        assert!(matches!(
            store.execute_digest_delete_authorized(empty_plan, Vec::new()),
            Err(ImageStoreError::DeleteNotFound(found)) if found == digest
        ));
        assert!(store.resolve_reference(&digest).unwrap().is_some());
    }

    #[test]
    fn digest_delete_rejects_removed_retargeted_substituted_and_added_inventory() {
        for drift in ["removed", "retargeted", "substituted", "added"] {
            let temp = tempfile::tempdir().unwrap();
            let store = LocalImageStore::open(temp.path()).unwrap();
            let authority = crate::authorization::surface::SurfaceMutationAuthority::for_test();
            let digest = format!("sha256:{}", "d".repeat(64));
            let other = format!("sha256:{}", "f".repeat(64));
            let original = "registry.example/acme/app:original";
            store.put_reference(&authority, original, &digest, "test", "{}").unwrap();
            let plan = store.prepare_digest_delete(&digest, true).unwrap();
            let auth = crate::authorization::surface::SurfaceAuthorization::compatibility();
            let origin = crate::authorization::RequestOrigin::cli_current().unwrap();
            let permits = plan.references().iter().map(|reference| {
                auth.authorize_image_binding(&origin, crate::authorization::Action::ImageDelete, reference, &digest, 1).unwrap()
            }).collect();

            match drift {
                "removed" => assert!(store.remove_reference_if_digest(original, &digest).unwrap()),
                "retargeted" => store.put_reference(&authority, original, &other, "test", "{}").unwrap(),
                "substituted" => {
                    assert!(store.remove_reference_if_digest(original, &digest).unwrap());
                    store.put_reference(&authority, "registry.example/acme/app:replacement", &digest, "test", "{}").unwrap();
                }
                "added" => store.put_reference(&authority, "registry.example/acme/app:added", &digest, "test", "{}").unwrap(),
                _ => unreachable!(),
            }

            assert!(matches!(store.execute_digest_delete_authorized(plan, permits), Err(ImageStoreError::DeleteInventoryChanged)), "drift={drift}");
            assert!(store.resolve_reference(&digest).unwrap().is_some(), "digest metadata removed for drift={drift}");
        }
    }

    #[test]
    fn authorized_prune_removes_only_the_selected_inventory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("open store");
        let selected = "registry.example/acme/selected:latest";
        let selected_digest = format!("sha256:{}", "b".repeat(64));
        let retained = "registry.example/acme/retained:latest";
        let retained_digest = format!("sha256:{}", "c".repeat(64));
        let authority = &crate::authorization::surface::SurfaceMutationAuthority::for_test();

        store
            .put_reference(
                authority,
                selected,
                &selected_digest,
                "application/vnd.oci.image.manifest.v1+json",
                "{\"schemaVersion\":2}",
            )
            .expect("selected record");
        store
            .put_reference(
                authority,
                retained,
                &retained_digest,
                "application/vnd.oci.image.manifest.v1+json",
                "{\"schemaVersion\":2}",
            )
            .expect("retained record");

        let auth = crate::authorization::surface::SurfaceAuthorization::compatibility();
        let permit = auth
            .authorize_image_binding(
                &crate::authorization::RequestOrigin::cli_current().expect("origin"),
                crate::authorization::Action::ImageDelete,
                selected,
                &selected_digest,
                1,
            )
            .expect("selected permit");

        assert_eq!(
            store
                .prune_references_authorized(vec![permit], &[selected.to_string()])
                .expect("selected prune"),
            1
        );
        let remaining = store.list_references().expect("remaining records");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].reference, retained);
        assert_eq!(remaining[0].digest, retained_digest);
    }

    #[test]
    fn default_open_rejects_legacy_image_directory() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("conf")).unwrap();
        let error = match LocalImageStore::open(temp.path()) {
            Ok(_) => panic!("legacy boundary"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("legacy-sled-importers"));
    }
}
