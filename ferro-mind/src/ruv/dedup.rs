use crate::ruv::distance;
use crate::ruv::embeddings::{EmbeddingProvider, HashEmbedding};
use crate::ruv::types::DistanceMetric;

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
