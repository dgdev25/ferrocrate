//! RVF-backed persistent vector storage.

use crate::ruv::types::SearchResult;
use rvf_runtime::{QueryOptions, RvfOptions, RvfStore as BackendStore};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
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
    backend: BackendStore,
    _path: PathBuf,
    dimensions: usize,
}

impl RvfStore {
    pub fn open_or_create<P: AsRef<Path>>(path: P, dimensions: usize) -> Result<Self> {
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
            backend,
            _path: path,
            dimensions,
        })
    }

    pub fn insert(&mut self, id: Option<&str>, vector: &[f32]) -> Result<()> {
        if vector.len() != self.dimensions {
            return Err(RvfStoreError::InvalidDimensions(vector.len()));
        }

        let rvf_id = stable_id(id, vector);
        self.backend
            .ingest_batch(&[vector], &[rvf_id], None)
            .map_err(|err| RvfStoreError::Runtime(err.to_string()))?;
        Ok(())
    }

    pub fn search(&self, query: &[f32], k: usize) -> Result<Vec<SearchResult>> {
        if query.len() != self.dimensions {
            return Err(RvfStoreError::InvalidDimensions(query.len()));
        }

        let results = self
            .backend
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
        self.backend.status().total_vectors as usize
    }
}

#[cfg(test)]
mod tests {
    use super::RvfStore;

    #[test]
    fn persists_vectors_across_restarts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("memory.rvf");

        {
            let mut store = RvfStore::open_or_create(&path, 3).expect("create");
            store
                .insert(Some("v1"), &[1.0, 0.0, 0.0])
                .expect("insert");
            assert_eq!(store.len(), 1);
        }

        {
            let store = RvfStore::open_or_create(&path, 3).expect("open");
            let hits = store.search(&[1.0, 0.0, 0.0], 1).expect("query");
            assert_eq!(hits.len(), 1);
        }
    }
}
