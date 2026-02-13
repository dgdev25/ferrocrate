//! Vector Memory with HNSW indexing via ruvector-core
//!
//! Provides O(log n) approximate nearest neighbor search instead of O(n) brute-force.
//! Uses HNSW (Hierarchical Navigable Small World) algorithm for efficient similarity search.

use crate::ruv::types::{DistanceMetric, SearchResult, VectorEntry, VectorId};
use ruvector_core::{VectorDB, types::{DbOptions, HnswConfig, SearchQuery}};
use std::sync::Arc;
use parking_lot::RwLock;

/// Vector Memory backed by ruvector-core with HNSW indexing
///
/// Provides O(log n) search complexity vs O(n) brute-force.
/// Suitable for large-scale vector similarity search in container
/// memory patterns, anomaly detection, and resource prediction.
pub struct VectorMemory {
    db: Arc<RwLock<Option<VectorDB>>>,
    entries: Vec<VectorEntry>,  // Fallback storage for when db not initialized
    default_dimensions: usize,
}

impl Default for VectorMemory {
    fn default() -> Self {
        Self {
            db: Arc::new(RwLock::new(None)),
            entries: Vec::new(),
            default_dimensions: 384,  // Default embedding dimension
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
        }
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
        self.entries.len()
    }

    /// Check if memory is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
}
