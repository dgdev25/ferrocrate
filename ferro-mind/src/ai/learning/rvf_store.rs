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

/// Persisted storage measurements for compression and capacity gates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RvfStoreMetrics {
    pub dimensions: usize,
    pub vectors: usize,
    pub file_size_bytes: u64,
    pub bytes_per_vector: Option<f64>,
}

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

    /// Flush pending vectors and return measured on-disk storage metrics.
    ///
    /// The measurements are deliberately descriptive: callers can enforce a
    /// product-specific size policy, while this layer never invents a recall
    /// or reconstruction-error guarantee that the backend does not expose.
    pub fn metrics(&self) -> Result<RvfStoreMetrics> {
        self.flush_pending()?;
        let backend = self.backend.lock();
        let status = backend.status();
        let vectors = status.total_vectors as usize;
        Ok(RvfStoreMetrics {
            dimensions: self.dimensions,
            vectors,
            file_size_bytes: status.file_size,
            bytes_per_vector: (vectors > 0).then(|| status.file_size as f64 / vectors as f64),
        })
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
    fn open_fails_closed_on_corrupt_file_without_silent_reset() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("corrupt.rvf");
        let garbage = b"not an rvf store: trailing junk bytes".to_vec();
        std::fs::write(&path, &garbage).expect("write garbage");

        let error = RvfStore::open_or_create(&path, 3).err().expect("corrupt store must fail");
        assert!(
            matches!(error, super::RvfStoreError::Runtime(_)),
            "unexpected error: {error:?}"
        );
        // Fail closed also means the corrupt artifact is left untouched.
        assert_eq!(std::fs::read(&path).expect("unchanged file"), garbage);
    }

    #[test]
    fn reopen_with_mismatched_dimensions_fails_closed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("dims.rvf");
        {
            let store = RvfStore::open_or_create(&path, 3).expect("create");
            store.insert(Some("v"), &[1.0, 0.0, 0.0]).expect("insert");
        }

        let error = RvfStore::open_or_create(&path, 4).err().expect("dimension mismatch");
        assert!(
            matches!(error, super::RvfStoreError::InvalidDimensions(3)),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn insert_rejects_wrong_dimension_vector() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = RvfStore::open_or_create(tmp.path().join("dim-check.rvf"), 3).expect("create");
        let error = store
            .insert(Some("bad"), &[1.0, 0.0])
            .err()
            .expect("wrong dimension must fail");
        assert!(
            matches!(error, super::RvfStoreError::InvalidDimensions(2)),
            "unexpected error: {error:?}"
        );
        assert_eq!(store.len(), 0);
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
        let metrics = store.metrics().expect("metrics");
        assert_eq!(metrics.dimensions, 3);
        assert_eq!(metrics.vectors, 1);
        assert!(metrics.file_size_bytes > 0);
        assert!(metrics.bytes_per_vector.is_some());
    }

    #[test]
    fn scalar_compression_preserves_a_thousand_vector_workload() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("compressed-large.rvf");
        let dimensions = 8;
        {
            let store = RvfStore::open_or_create_with_compression(
                &path,
                dimensions,
                CompressionProfile::Scalar,
            )
            .expect("create compressed store");
            for index in 0..1_000u32 {
                let mut vector = [0.0_f32; 8];
                vector[(index as usize) % dimensions] = 1.0;
                vector[((index as usize) + 1) % dimensions] = (index + 1) as f32;
                store
                    .insert(Some(&format!("compressed-{index}")), &vector)
                    .expect("insert compressed vector");
            }
            assert_eq!(store.len(), 1_000);
        }

        let reopened = RvfStore::open_or_create(&path, dimensions).expect("reopen compressed");
        assert_eq!(reopened.len(), 1_000);
        let hits = reopened
            .search(&[1_000.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0], 10)
            .expect("query compressed store");
        assert_eq!(hits.len(), 10);
    }

    /// Regression gate for the persistent compression profile: on an
    /// identical workload, the Scalar profile must never produce a larger
    /// on-disk artifact than the default None profile (size
    /// non-regression), and it must return the same top-1 query results
    /// (compatibility). Measured against rvf-runtime 0.2.0, where the
    /// stored profile is accepted but not yet applied — see
    /// docs/evidence/ai/2026-08-21-quantization-regression-gates.md.
    #[test]
    fn scalar_profile_size_and_query_parity_gate() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dimensions = 8;
        let workload: Vec<[f32; 8]> = (0..512u32)
            .map(|index| {
                let mut vector = [0.0_f32; 8];
                vector[(index as usize) % dimensions] = 1.0;
                vector[((index as usize) + 1) % dimensions] = (index % 97) as f32 / 97.0;
                vector[((index as usize) + 3) % dimensions] = (index % 13) as f32 / 13.0;
                vector
            })
            .collect();

        let build = |path: std::path::PathBuf, compression: CompressionProfile| {
            let store =
                RvfStore::open_or_create_with_compression(&path, dimensions, compression)
                    .expect("create store");
            for (index, vector) in workload.iter().enumerate() {
                store
                    .insert(Some(&format!("v-{index}")), vector)
                    .expect("insert vector");
            }
            let metrics = store.metrics().expect("metrics");
            drop(store);
            metrics
        };

        let plain = build(tmp.path().join("plain.rvf"), CompressionProfile::None);
        let scalar = build(tmp.path().join("scalar.rvf"), CompressionProfile::Scalar);

        assert_eq!(plain.vectors, 512);
        assert_eq!(scalar.vectors, 512);
        assert!(
            scalar.file_size_bytes <= plain.file_size_bytes,
            "scalar profile file {} bytes is larger than plain {} bytes",
            scalar.file_size_bytes,
            plain.file_size_bytes
        );

        // Compatibility: both profiles must answer probes identically.
        let plain_store = RvfStore::open_or_create(tmp.path().join("plain.rvf"), dimensions)
            .expect("open plain");
        let scalar_store = RvfStore::open_or_create(tmp.path().join("scalar.rvf"), dimensions)
            .expect("open scalar");
        for probe in [0usize, 7, 100, 511] {
            let query = workload[probe];
            let plain_top = plain_store.search(&query, 1).expect("plain query");
            let scalar_top = scalar_store.search(&query, 1).expect("scalar query");
            assert_eq!(plain_top.len(), 1);
            assert_eq!(scalar_top.len(), 1);
            assert_eq!(
                plain_top[0].id, scalar_top[0].id,
                "top-1 result differs at probe {probe}"
            );
        }
    }
}
