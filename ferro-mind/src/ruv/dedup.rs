use crate::ruv::distance;
use crate::ruv::embeddings::{EmbeddingProvider, HashEmbedding};
#[cfg(feature = "rvf-persistence")]
use crate::ruv::rvf_cache::RvfDedupCache;
use crate::ruv::types::DistanceMetric;
#[cfg(feature = "rvf-persistence")]
use std::path::Path;

#[derive(Debug, Clone)]
pub struct DedupConfig {
    pub dimensions: usize,
    pub threshold: f32,
    pub metric: DistanceMetric,
}

impl Default for DedupConfig {
    fn default() -> Self {
        Self {
            dimensions: 384,
            threshold: 0.1,
            metric: DistanceMetric::Cosine,
        }
    }
}

pub fn is_duplicate(
    config: &DedupConfig,
    a: &str,
    b: &str,
    provider: Option<&dyn EmbeddingProvider>,
) -> Result<bool, String> {
    let fallback = HashEmbedding::new(config.dimensions);
    let engine = provider.unwrap_or(&fallback);
    let va = engine.embed(a).map_err(|err| err.to_string())?;
    let vb = engine.embed(b).map_err(|err| err.to_string())?;
    let score = distance::distance(&va, &vb, config.metric).map_err(|err| err.to_string())?;
    Ok(score <= config.threshold)
}

#[cfg(feature = "rvf-persistence")]
pub fn is_duplicate_with_cache(
    config: &DedupConfig,
    a_key: &str,
    a: &str,
    b: &str,
    cache_path: &Path,
    provider: Option<&dyn EmbeddingProvider>,
) -> Result<bool, String> {
    let mut cache = RvfDedupCache::open(
        cache_path,
        config.dimensions,
        config.threshold,
        config.metric,
    )?;
    cache.record(a_key, a)?;
    if cache.nearest_duplicate_key(b)?.is_some() {
        return Ok(true);
    }
    is_duplicate(config, a, b, provider)
}
