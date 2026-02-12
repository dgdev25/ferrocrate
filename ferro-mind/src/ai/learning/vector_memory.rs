use crate::ruv::distance;
use crate::ruv::types::{DistanceMetric, SearchResult, VectorEntry, VectorId};

#[derive(Default)]
pub struct VectorMemory {
    entries: Vec<VectorEntry>,
}

impl VectorMemory {
    pub fn insert(&mut self, entry: VectorEntry) {
        self.entries.push(entry);
    }

    pub fn search(&self, query: &[f32], k: usize, metric: DistanceMetric) -> Vec<SearchResult> {
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
}
