//! Vector Memory with HNSW indexing via ruvector-core
//!
//! Provides O(log n) approximate nearest neighbor search instead of O(n) brute-force.
//! Uses HNSW (Hierarchical Navigable Small World) algorithm for efficient similarity search.

use crate::ruv::types::{DistanceMetric, SearchResult, VectorEntry, VectorId};
use ruvector_core::{VectorDB, types::{DbOptions, HnswConfig, SearchQuery}};
use std::sync::Arc;
use parking_lot::RwLock;
#[cfg(feature = "rvf-persistence")]
use std::path::Path;

#[cfg(feature = "rvf-persistence")]
use crate::ai::learning::rvf_store::{RvfStore, stable_id};

/// Vector Memory backed by ruvector-core with HNSW indexing
///
/// Provides O(log n) search complexity vs O(n) brute-force.
/// Suitable for large-scale vector similarity search in container
/// memory patterns, anomaly detection, and resource prediction.
pub struct VectorMemory {
    db: Arc<RwLock<Option<VectorDB>>>,
    entries: Vec<VectorEntry>,  // Fallback storage for when db not initialized
    default_dimensions: usize,
    #[cfg(feature = "rvf-persistence")]
    rvf: Option<RvfStore>,
    #[cfg(feature = "rvf-persistence")]
    entry_index: std::collections::HashMap<u64, usize>,
}

impl Default for VectorMemory {
    fn default() -> Self {
        Self {
            db: Arc::new(RwLock::new(None)),
            entries: Vec::new(),
            default_dimensions: 384,  // Default embedding dimension
            #[cfg(feature = "rvf-persistence")]
            rvf: None,
            #[cfg(feature = "rvf-persistence")]
            entry_index: std::collections::HashMap::new(),
        }
    }
}

impl VectorMemory {
    /// Create a new VectorMemory with specified dimensions
    pub fn with_dimensions(dimensions: usize) -> Self {
        Self {
            db: Arc::new(RwLock::new(None)),
            entries: Vec::new(),
            default_dimensions: dimensions,
            #[cfg(feature = "rvf-persistence")]
            rvf: None,
            #[cfg(feature = "rvf-persistence")]
            entry_index: std::collections::HashMap::new(),
        }
    }

    /// Create vector memory using backend selection from `FERROCRATE_AI_BACKEND`.
    ///
    /// Supported values:
    /// - `rvf` (requires `rvf-persistence`)
    /// - `legacy` (in-memory)
    #[cfg(feature = "rvf-persistence")]
    pub fn with_backend(path: &Path, dimensions: usize) -> Result<Self, String> {
        let backend = std::env::var("FERROCRATE_AI_BACKEND").unwrap_or_else(|_| "rvf".to_string());
        if backend.eq_ignore_ascii_case("legacy") {
            return Ok(Self::with_dimensions(dimensions));
        }
        Self::persistent(path, dimensions)
    }

    /// Create a persistent vector memory backed by RVF.
    #[cfg(feature = "rvf-persistence")]
    pub fn persistent(path: &Path, dimensions: usize) -> Result<Self, String> {
        let rvf = RvfStore::open_or_create(path, dimensions).map_err(|err| err.to_string())?;
        Ok(Self {
            db: Arc::new(RwLock::new(None)),
            entries: Vec::new(),
            default_dimensions: dimensions,
            rvf: Some(rvf),
            entry_index: std::collections::HashMap::new(),
        })
    }

    /// Initialize the HNSW-backed database
    fn init_db(&self, dimensions: usize) -> VectorDB {
        let options = DbOptions {
            dimensions,
            distance_metric: ruvector_core::types::DistanceMetric::Cosine,
            storage_path: ":memory:".to_string(),  // In-memory for vector memory
            hnsw_config: Some(HnswConfig {
                m: 16,                // Number of connections per node
                ef_construction: 100, // Construction-time search depth
                ef_search: 50,        // Search-time search depth
                max_elements: 1_000_000,
            }),
            quantization: None,
        };
        VectorDB::new(options).expect("Failed to initialize HNSW index")
    }

    /// Insert a vector entry into memory
    pub fn insert(&mut self, entry: VectorEntry) {
        #[cfg(feature = "rvf-persistence")]
        if let Some(rvf) = self.rvf.as_ref() {
            let stable = stable_id(entry.id.as_deref(), &entry.vector);
            if rvf
                .insert(entry.id.as_deref(), &entry.vector)
                .is_ok()
            {
                self.entries.push(entry);
                self.entry_index.insert(stable, self.entries.len() - 1);
            }
            return;
        }

        let dimensions = if entry.vector.is_empty() {
            self.default_dimensions
        } else {
            entry.vector.len()
        };

        // Initialize DB on first insert if needed
        {
            let mut db_guard = self.db.write();
            if db_guard.is_none() {
                *db_guard = Some(self.init_db(dimensions));
            }
        }

        // Insert into HNSW index
        {
            let db_guard = self.db.read();
            if let Some(db) = db_guard.as_ref() {
                let ruv_entry = ruvector_core::types::VectorEntry {
                    id: entry.id.clone(),
                    vector: entry.vector.clone(),
                    metadata: entry.metadata.clone(),
                };
                let _ = db.insert(ruv_entry);
            }
        }

        // Also keep in local storage for fallback
        self.entries.push(entry);
    }

    /// Search for k nearest neighbors using HNSW algorithm
    ///
    /// Returns results sorted by distance (closest first).
    /// Uses O(log n) approximate nearest neighbor search for Cosine similarity.
    /// Falls back to brute-force O(n) for other distance metrics.
    pub fn search(&self, query: &[f32], k: usize, metric: DistanceMetric) -> Vec<SearchResult> {
        #[cfg(feature = "rvf-persistence")]
        if let Some(rvf) = self.rvf.as_ref() {
            if metric == DistanceMetric::Cosine {
                if let Ok(results) = rvf.search(query, k) {
                    return results
                        .into_iter()
                        .map(|mut result| {
                            if let Ok(id_num) = result.id.parse::<u64>() {
                                if let Some(index) = self.entry_index.get(&id_num) {
                                    let entry = &self.entries[*index];
                                    result.id = entry
                                        .id
                                        .clone()
                                        .unwrap_or_else(|| result.id.clone());
                                    result.metadata = entry.metadata.clone();
                                }
                            }
                            result
                        })
                        .collect();
                }
            }
        }

        // HNSW is only configured for Cosine similarity - use brute-force for other metrics
        if metric == DistanceMetric::Cosine {
            // Try HNSW search first for Cosine similarity
            let db_guard = self.db.read();
            if let Some(db) = db_guard.as_ref() {
                let search_query = SearchQuery {
                    vector: query.to_vec(),
                    k,
                    filter: None,
                    ef_search: Some(50),
                };

                if let Ok(results) = db.search(search_query) {
                    return results
                        .into_iter()
                        .map(|r| SearchResult {
                            id: VectorId::from(r.id),
                            score: r.score,
                            vector: r.vector,
                            metadata: r.metadata,
                        })
                        .collect();
                }
            }
        }

        // Fallback to brute-force O(n) for non-Cosine metrics or if HNSW fails
        self.search_bruteforce(query, k, metric)
    }

    /// Brute-force O(n) search as fallback
    fn search_bruteforce(&self, query: &[f32], k: usize, metric: DistanceMetric) -> Vec<SearchResult> {
        use crate::ruv::distance;

        let mut scored = Vec::new();
        for entry in &self.entries {
            let score = match distance::distance(query, &entry.vector, metric) {
                Ok(score) => score,
                Err(_) => continue,
            };
            scored.push(SearchResult {
                id: entry.id.clone().unwrap_or_else(|| VectorId::from("unknown")),
                score,
                vector: None,
                metadata: entry.metadata.clone(),
            });
        }
        // Handle NaN gracefully - use Equal ordering for NaN comparisons
        scored.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(k);
        scored
    }

    /// Get the number of stored vectors
    pub fn len(&self) -> usize {
        #[cfg(feature = "rvf-persistence")]
        if let Some(rvf) = self.rvf.as_ref() {
            return rvf.len();
        }
        self.entries.len()
    }

    /// Check if memory is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn vector_memory_insert_and_search() {
        let mut memory = VectorMemory::with_dimensions(3);

        // Insert some vectors
        memory.insert(VectorEntry {
            id: Some(VectorId::from("vec1")),
            vector: vec![1.0, 0.0, 0.0],
            metadata: Some(HashMap::new()),
        });
        memory.insert(VectorEntry {
            id: Some(VectorId::from("vec2")),
            vector: vec![0.0, 1.0, 0.0],
            metadata: Some(HashMap::new()),
        });
        memory.insert(VectorEntry {
            id: Some(VectorId::from("vec3")),
            vector: vec![1.0, 1.0, 0.0],
            metadata: Some(HashMap::new()),
        });

        // Search for closest to [1.0, 0.1, 0.0]
        let results = memory.search(&[1.0, 0.1, 0.0], 2, DistanceMetric::Euclidean);

        assert_eq!(results.len(), 2);
        // vec1 should be closest (distance ~0.1)
        assert_eq!(results[0].id.as_str(), "vec1");
    }

    #[test]
    fn vector_memory_handles_empty() {
        let memory = VectorMemory::default();
        let results = memory.search(&[1.0, 2.0, 3.0], 5, DistanceMetric::Euclidean);
        assert!(results.is_empty());
    }

    #[cfg(feature = "rvf-persistence")]
    #[test]
    fn persistent_memory_survives_reopen() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("vmem.rvf");

        {
            let mut memory = VectorMemory::persistent(&path, 3).expect("create");
            memory.insert(VectorEntry {
                id: Some(VectorId::from("vec1")),
                vector: vec![1.0, 0.0, 0.0],
                metadata: Some(HashMap::new()),
            });
            assert_eq!(memory.len(), 1);
        }

        {
            let memory = VectorMemory::persistent(&path, 3).expect("reopen");
            let results = memory.search(&[1.0, 0.0, 0.0], 1, DistanceMetric::Cosine);
            assert_eq!(results.len(), 1);
            assert!(!memory.is_empty());
        }
    }

    #[cfg(feature = "rvf-persistence")]
    #[test]
    fn backend_selector_respects_legacy_env() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("backend.rvf");
        unsafe { std::env::set_var("FERROCRATE_AI_BACKEND", "legacy"); }
        let mut memory = VectorMemory::with_backend(&path, 3).expect("backend");
        memory.insert(VectorEntry {
            id: Some(VectorId::from("legacy")),
            vector: vec![0.0, 0.0, 1.0],
            metadata: Some(HashMap::new()),
        });
        let results = memory.search(&[0.0, 0.0, 1.0], 1, DistanceMetric::Cosine);
        assert_eq!(results.len(), 1);
        unsafe { std::env::remove_var("FERROCRATE_AI_BACKEND"); }
    }

    #[cfg(feature = "rvf-persistence")]
    #[test]
    fn non_cosine_metric_falls_back_to_bruteforce() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("fallback.rvf");
        let mut memory = VectorMemory::persistent(&path, 3).expect("create");
        memory.insert(VectorEntry {
            id: Some(VectorId::from("a")),
            vector: vec![1.0, 0.0, 0.0],
            metadata: Some(HashMap::new()),
        });
        memory.insert(VectorEntry {
            id: Some(VectorId::from("b")),
            vector: vec![0.0, 1.0, 0.0],
            metadata: Some(HashMap::new()),
        });
        let results = memory.search(&[0.9, 0.0, 0.0], 1, DistanceMetric::Euclidean);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id.as_str(), "a");
    }

    #[cfg(feature = "rvf-persistence")]
    #[test]
    fn is_empty_reflects_persistent_data() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("empty-check.rvf");
        {
            let mut memory = VectorMemory::persistent(&path, 3).expect("create");
            assert!(memory.is_empty());
            memory.insert(VectorEntry {
                id: Some(VectorId::from("vec1")),
                vector: vec![1.0, 0.0, 0.0],
                metadata: Some(HashMap::new()),
            });
            assert!(!memory.is_empty());
        }
        let reopened = VectorMemory::persistent(&path, 3).expect("reopen");
        assert!(!reopened.is_empty());
    }

    #[cfg(feature = "rvf-persistence")]
    #[test]
    fn backend_parity_workload() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("parity.rvf");
        let dims = 64usize;
        let inserts = 1200usize;
        let queries = 4000usize;

        let mut memory = VectorMemory::with_backend(&path, dims).expect("backend");

        for i in 0..inserts {
            let mut vector = Vec::with_capacity(dims);
            for d in 0..dims {
                // Deterministic feature values to keep both backends comparable.
                let value = (((i * 31 + d * 17) % 997) as f32) / 997.0;
                vector.push(value);
            }
            memory.insert(VectorEntry {
                id: Some(VectorId::from(format!("v{i}"))),
                vector,
                metadata: None,
            });
        }
        assert_eq!(memory.len(), inserts);

        let mut total_hits = 0usize;
        for q in 0..queries {
            let mut query = Vec::with_capacity(dims);
            for d in 0..dims {
                let value = (((q * 29 + d * 13 + 7) % 997) as f32) / 997.0;
                query.push(value);
            }
            let hits = memory.search(&query, 8, DistanceMetric::Cosine);
            total_hits += hits.len();
        }
        assert!(total_hits > 0);
    }
}
