// Adapted from MIT-licensed ruvector-core (https://github.com/ruvnet/ruvector)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type VectorId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistanceMetric {
    Euclidean,
    Cosine,
    DotProduct,
    Manhattan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorEntry {
    pub id: Option<VectorId>,
    pub vector: Vec<f32>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    pub vector: Vec<f32>,
    pub k: usize,
    pub filter: Option<HashMap<String, serde_json::Value>>,
    pub ef_search: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub id: VectorId,
    pub score: f32,
    pub vector: Option<Vec<f32>>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbOptions {
    pub dimensions: usize,
    pub distance_metric: DistanceMetric,
    pub storage_path: String,
    pub hnsw_config: Option<HnswConfig>,
    pub quantization: Option<QuantizationConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HnswConfig {
    pub m: usize,
    pub ef_construction: usize,
    pub ef_search: usize,
    pub max_elements: usize,
}

impl Default for HnswConfig {
    fn default() -> Self {
        Self {
            m: 32,
            ef_construction: 200,
            ef_search: 100,
            max_elements: 10_000_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuantizationConfig {
    None,
    Scalar,
    Product { subspaces: usize, k: usize },
    Binary,
}

impl Default for DbOptions {
    fn default() -> Self {
        Self {
            dimensions: 384,
            distance_metric: DistanceMetric::Cosine,
            storage_path: "./ruvector.db".to_string(),
            hnsw_config: Some(HnswConfig::default()),
            quantization: Some(QuantizationConfig::Scalar),
        }
    }
}
