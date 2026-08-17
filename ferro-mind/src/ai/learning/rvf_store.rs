//! RVF-backed persistent vector storage.

use crate::ruv::types::SearchResult;
use parking_lot::Mutex;
use rvf_runtime::{
    options::CompressionProfile, QueryOptions, RvfOptions, RvfStore as BackendStore,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RvfStoreError {
    #[error("invalid dimensions: {0}")]
    InvalidDimensions(usize),
    #[error("rvf error: {0}")]
    Runtime(String),
}

type Result<T> = std::result::Result<T, RvfStoreError>;

/// Stable ID mapping for RVF's u64 IDs.
pub(crate) fn stable_id(id: Option<&str>, vector: &[f32]) -> u64 {
    let mut hasher = DefaultHasher::new();
    match id {
        Some(id) => id.hash(&mut hasher),
        None => {
            for value in vector {
                value.to_bits().hash(&mut hasher);
            }
        }
    }
    hasher.finish().max(1)
}

pub struct RvfStore {
    backend: Mutex<BackendStore>,
    _path: PathBuf,
    dimensions: usize,
    pending: Mutex<PendingBatch>,
    has_pending: AtomicBool,
}

#[derive(Default)]
struct PendingBatch {
    vectors: Vec<Vec<f32>>,
    ids: Vec<u64>,
}

impl RvfStore {
    const FLUSH_BATCH_SIZE: usize = 256;

    pub fn open_or_create<P: AsRef<Path>>(path: P, dimensions: usize) -> Result<Self> {
        Self::open_or_create_with_compression(path, dimensions, CompressionProfile::None)
    }

    /// Open an existing RVF store or create one with the requested persistent
    /// vector-compression profile. The profile is applied at file creation;
    /// reopening an existing artifact never rewrites it implicitly.
    pub fn open_or_create_with_compression<P: AsRef<Path>>(
        path: P,
        dimensions: usize,
        compression: CompressionProfile,
    ) -> Result<Self> {
        if dimensions == 0 || dimensions > u16::MAX as usize {
            return Err(RvfStoreError::InvalidDimensions(dimensions));
        }

        let path = path.as_ref().to_path_buf();
        let backend = if path.exists() {
            BackendStore::open(&path).map_err(|err| RvfStoreError::Runtime(err.to_string()))?
        } else {
            let options = RvfOptions {
                dimension: dimensions as u16,
                metric: rvf_runtime::options::DistanceMetric::Cosine,
                compression,
                ..Default::default()
            };
            BackendStore::create(&path, options)
                .map_err(|err| RvfStoreError::Runtime(err.to_string()))?
        };

        let detected_dimensions = backend.dimension() as usize;
        if detected_dimensions != dimensions {
            return Err(RvfStoreError::InvalidDimensions(detected_dimensions));
        }

        Ok(Self {
            backend: Mutex::new(backend),
            _path: path,
            dimensions,
            pending: Mutex::new(PendingBatch::default()),
            has_pending: AtomicBool::new(false),
        })
    }

    pub fn insert(&self, id: Option<&str>, vector: &[f32]) -> Result<()> {
        if vector.len() != self.dimensions {
            return Err(RvfStoreError::InvalidDimensions(vector.len()));
        }

        let rvf_id = stable_id(id, vector);
        {
            let mut pending = self.pending.lock();
            pending.vectors.push(vector.to_vec());
            pending.ids.push(rvf_id);
            self.has_pending.store(true, Ordering::Relaxed);
            if pending.vectors.len() >= Self::FLUSH_BATCH_SIZE {
                drop(pending);
                self.flush_pending()?;
            }
        }
        Ok(())
    }

    pub fn search(&self, query: &[f32], k: usize) -> Result<Vec<SearchResult>> {
        if query.len() != self.dimensions {
            return Err(RvfStoreError::InvalidDimensions(query.len()));
        }
        self.flush_pending()?;

        let backend = self.backend.lock();
        let results = backend
            .query(query, k, &QueryOptions::default())
            .map_err(|err| RvfStoreError::Runtime(err.to_string()))?;

        Ok(results
            .into_iter()
            .map(|result| SearchResult {
                id: result.id.to_string(),
                score: result.distance,
                vector: None,
                metadata: None,
            })
            .collect())
    }

    pub fn len(&self) -> usize {
        let committed = self.backend.lock().status().total_vectors as usize;
        let buffered = if self.has_pending.load(Ordering::Relaxed) {
            self.pending.lock().vectors.len()
        } else {
            0
        };
        committed + buffered
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn flush_pending(&self) -> Result<()> {
        if !self.has_pending.load(Ordering::Relaxed) {
            return Ok(());
        }
        let mut pending = self.pending.lock();
        if pending.vectors.is_empty() {
            self.has_pending.store(false, Ordering::Relaxed);
            return Ok(());
        }

        let refs: Vec<&[f32]> = pending.vectors.iter().map(|v| v.as_slice()).collect();
        let ids = pending.ids.clone();
        let mut backend = self.backend.lock();
        backend
            .ingest_batch(&refs, &ids, None)
            .map_err(|err| RvfStoreError::Runtime(err.to_string()))?;
        pending.vectors.clear();
        pending.ids.clear();
        self.has_pending.store(false, Ordering::Relaxed);
        Ok(())
    }
}

impl Drop for RvfStore {
    fn drop(&mut self) {
        let _ = self.flush_pending();
    }
}

#[cfg(test)]
mod tests {
    use super::{stable_id, RvfStore};
    use rvf_runtime::options::CompressionProfile;

    #[test]
    fn persists_vectors_across_restarts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("memory.rvf");

        {
            let store = RvfStore::open_or_create(&path, 3).expect("create");
            store.insert(Some("v1"), &[1.0, 0.0, 0.0]).expect("insert");
            assert_eq!(store.len(), 1);
        }

        {
            let store = RvfStore::open_or_create(&path, 3).expect("open");
            let hits = store.search(&[1.0, 0.0, 0.0], 1).expect("query");
            assert_eq!(hits.len(), 1);
        }
    }

    #[test]
    fn persists_and_queries_a_thousand_vectors_after_restart() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("large-memory.rvf");
        let dimensions = 8;
        let target = {
            let store = RvfStore::open_or_create(&path, dimensions).expect("create");
            for index in 0..1_000u32 {
                let mut vector = [0.0_f32; 8];
                vector[(index as usize) % dimensions] = 1.0;
                vector[((index as usize) + 1) % dimensions] = (index + 1) as f32;
                store
                    .insert(Some(&format!("vector-{index}")), &vector)
                    .expect("insert vector");
            }
            assert_eq!(store.len(), 1_000);
            [1_000.0_f32, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0]
        };

        let reopened = RvfStore::open_or_create(&path, dimensions).expect("reopen");
        assert_eq!(reopened.len(), 1_000);
        let hits = reopened.search(&target, 10).expect("query after restart");
        assert_eq!(hits.len(), 10);
        let expected_id = stable_id(
            Some("vector-999"),
            &[1_000.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0],
        );
        assert!(hits.iter().any(|hit| hit.id == expected_id.to_string()));
    }

    #[test]
    fn scalar_compression_persists_and_remains_queryable_after_restart() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("compressed.rvf");
        {
            let store =
                RvfStore::open_or_create_with_compression(&path, 3, CompressionProfile::Scalar)
                    .expect("create compressed store");
            store
                .insert(Some("compressed-vector"), &[0.25, 0.5, 0.75])
                .expect("insert");
        }

        let store = RvfStore::open_or_create(&path, 3).expect("reopen compressed store");
        let hits = store
            .search(&[0.25, 0.5, 0.75], 1)
            .expect("query compressed store");
        assert_eq!(hits.len(), 1);
    }
}
