use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[cfg(feature = "legacy-sled-importers")]
const IMAGE_INDEX_TREE: &str = "image_index";
#[cfg(feature = "legacy-sled-importers")]
const IMAGE_DIGEST_TREE: &str = "image_digest_index";
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

#[derive(Debug, Error)]
pub enum ImageStoreError {
    #[error("failed to open image store: {0}")]
    Open(#[from] rusqlite::Error),
    #[error("failed to lock image store: {0}")]
    Lock(String),
    #[cfg(feature = "legacy-sled-importers")]
    #[error("failed to read legacy image store: {0}")]
    Legacy(#[from] sled::Error),
    #[error("legacy image store detected; reopen with the `legacy-sled-importers` feature")]
    LegacyMigrationRequired,
    #[error("image store io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to encode image record: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("failed to decode image record: {0}")]
    Decode(#[source] serde_json::Error),
    #[error("image authorization binding failed: {0}")]
    Authorization(String),
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

#[cfg(feature = "legacy-sled-importers")]
fn migrate_legacy_sled(path: &Path, db: &Connection) -> Result<(), ImageStoreError> {
    let marker = PathBuf::from(format!(
        "{}.{}.migrated",
        path.display(),
        IMAGE_SQLITE_SUFFIX
    ));
    if marker.exists() || !path.join("conf").exists() {
        return Ok(());
    }
    let legacy = sled::open(path)?;
    let references = legacy.open_tree(IMAGE_INDEX_TREE)?;
    for entry in &references {
        let (_, value) = entry?;
        let record =
            serde_json::from_slice::<ImageRecord>(&value).map_err(ImageStoreError::Decode)?;
        insert_image_record(db, &record)?;
    }
    let digests = legacy.open_tree(IMAGE_DIGEST_TREE)?;
    for entry in &digests {
        let (_, value) = entry?;
        let record =
            serde_json::from_slice::<ImageRecord>(&value).map_err(ImageStoreError::Decode)?;
        insert_image_digest(db, &record)?;
    }
    db.execute_batch("PRAGMA wal_checkpoint(FULL);")?;
    std::fs::write(marker, b"image-store-migration-v1\n")?;
    Ok(())
}

#[cfg(feature = "legacy-sled-importers")]
fn insert_image_record(db: &Connection, record: &ImageRecord) -> Result<(), ImageStoreError> {
    db.execute(
        "INSERT OR IGNORE INTO image_references
         (reference, digest, manifest_media_type, manifest_json, created_at_unix)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            record.reference,
            record.digest,
            record.manifest_media_type,
            record.manifest_json,
            record.created_at_unix as i64
        ],
    )?;
    Ok(())
}

#[cfg(feature = "legacy-sled-importers")]
fn insert_image_digest(db: &Connection, record: &ImageRecord) -> Result<(), ImageStoreError> {
    db.execute(
        "INSERT OR IGNORE INTO image_digests
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
    Ok(())
}

impl LocalImageStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ImageStoreError> {
        let legacy_path = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&legacy_path)?;
        let db_path = PathBuf::from(format!("{}.{}", legacy_path.display(), IMAGE_SQLITE_SUFFIX));
        if !db_path.exists() && legacy_path.join("conf").exists() {
            #[cfg(not(feature = "legacy-sled-importers"))]
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
        #[cfg(feature = "legacy-sled-importers")]
        migrate_legacy_sled(&legacy_path, &db)?;
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
        let requested_digest = reference.rsplit_once('@').map(|(_, digest)| digest);
        if let Some(digest) = requested_digest {
            match db.query_row(
                "SELECT reference, digest, manifest_media_type, manifest_json, created_at_unix
                 FROM image_digests WHERE digest = ?1",
                params![digest],
                image_record_from_row,
            ) {
                Ok(record) => return Ok(Some(record)),
                Err(rusqlite::Error::QueryReturnedNoRows) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(None)
    }

    fn remove_reference(&self, reference: &str) -> Result<bool, ImageStoreError> {
        let db = self
            .db
            .lock()
            .map_err(|error| ImageStoreError::Lock(error.to_string()))?;
        Ok(db.execute(
            "DELETE FROM image_references WHERE reference = ?1",
            params![reference],
        )? > 0)
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
        if permits.is_empty() {
            return Ok(0);
        }
        let result = {
            let authority = permits[0].mutation_authority();
            self.prune_references(&authority)
        };
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

    #[cfg(feature = "legacy-sled-importers")]
    #[test]
    fn migrates_legacy_sled_image_indexes_and_keeps_rollback_copy() {
        let temp = tempfile::tempdir().unwrap();
        let legacy = sled::open(temp.path()).unwrap();
        let record = super::ImageRecord {
            reference: "repo/app:legacy".to_string(),
            digest: format!("sha256:{}", "d".repeat(64)),
            manifest_media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            manifest_json: "{}".to_string(),
            created_at_unix: 7,
        };
        legacy
            .open_tree(super::IMAGE_INDEX_TREE)
            .unwrap()
            .insert(
                record.reference.as_bytes(),
                serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
        legacy
            .open_tree(super::IMAGE_DIGEST_TREE)
            .unwrap()
            .insert(
                record.digest.as_bytes(),
                serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
        legacy.flush().unwrap();
        drop(legacy);

        let store = LocalImageStore::open(temp.path()).unwrap();
        assert_eq!(
            store.resolve_reference(&record.reference).unwrap(),
            Some(record.clone())
        );
        assert_eq!(
            store
                .resolve_reference(&format!("repo/app@{}", record.digest))
                .unwrap(),
            Some(record)
        );
        assert!(temp.path().with_extension("sqlite").is_file());
        assert!(temp.path().with_extension("sqlite.migrated").is_file());
        assert!(temp.path().join("conf").is_file());
    }

    #[cfg(not(feature = "legacy-sled-importers"))]
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
