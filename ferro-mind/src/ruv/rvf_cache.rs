use std::collections::HashMap;
use std::path::Path;

use crate::ruv::distance;
use crate::ruv::embeddings::{EmbeddingProvider, HashEmbedding};
use crate::ruv::types::{DistanceMetric, VectorEntry, VectorId};

#[cfg(feature = "rvf-persistence")]
use crate::ai::learning::vector_memory::VectorMemory;

/// Persistent duplicate cache backed by RVF.
#[cfg(feature = "rvf-persistence")]
pub struct RvfDedupCache {
    memory: VectorMemory,
    embedder: HashEmbedding,
    threshold: f32,
    metric: DistanceMetric,
}

#[cfg(feature = "rvf-persistence")]
impl RvfDedupCache {
    pub fn open(
        path: &Path,
        dimensions: usize,
        threshold: f32,
        metric: DistanceMetric,
    ) -> Result<Self, String> {
        let memory = VectorMemory::with_backend(path, dimensions)?;
        Ok(Self {
            memory,
            embedder: HashEmbedding::new(dimensions),
            threshold,
            metric,
        })
    }

    pub fn record(&mut self, key: &str, payload: &str) -> Result<(), String> {
        let vector = self
            .embedder
            .embed(payload)
            .map_err(|err| err.to_string())?;
        let mut metadata = HashMap::new();
        metadata.insert("key".to_string(), serde_json::json!(key));
        self.memory.insert(VectorEntry {
            id: Some(VectorId::from(key)),
            vector,
            metadata: Some(metadata),
        });
        Ok(())
    }

    pub fn nearest_duplicate_key(&self, payload: &str) -> Result<Option<String>, String> {
        let vector = self
            .embedder
            .embed(payload)
            .map_err(|err| err.to_string())?;
        let results = self.memory.search(&vector, 1, self.metric);
        let Some(result) = results.first() else {
            return Ok(None);
        };
        let duplicate = result.score <= self.threshold;
        if !duplicate {
            return Ok(None);
        }

        if let Some(meta) = &result.metadata {
            if let Some(key) = meta.get("key").and_then(|value| value.as_str()) {
                return Ok(Some(key.to_string()));
            }
        }
        Ok(Some(result.id.to_string()))
    }
}

#[cfg(feature = "rvf-persistence")]
pub fn cached_duplicate_check(
    cache: &RvfDedupCache,
    a: &str,
    b: &str,
    provider: Option<&dyn EmbeddingProvider>,
) -> Result<bool, String> {
    let fallback = HashEmbedding::new(cache.embedder.dimensions());
    let engine = provider.unwrap_or(&fallback);
    let va = engine.embed(a).map_err(|err| err.to_string())?;
    let vb = engine.embed(b).map_err(|err| err.to_string())?;
    let score = distance::distance(&va, &vb, cache.metric).map_err(|err| err.to_string())?;
    Ok(score <= cache.threshold)
}

#[cfg(all(test, feature = "rvf-persistence"))]
mod tests {
    use super::*;

    #[test]
    fn cache_records_and_finds_duplicate() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("dedup-cache.rvf");
        let mut cache = RvfDedupCache::open(&path, 32, 0.25, DistanceMetric::Cosine).expect("open");
        cache.record("layer-a", "hello world").expect("record");
        let key = cache.nearest_duplicate_key("hello world").expect("query");
        assert_eq!(key.as_deref(), Some("layer-a"));
    }
}
