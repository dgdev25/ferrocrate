// Adapted from MIT-licensed ruvector-core (https://github.com/ruvnet/ruvector)
//
// Embedding providers for semantic search:
// - HashEmbedding: Fast hash-based (not semantic, for testing only)
// - OnnxEmbedding: Real semantic embeddings via ONNX/tract

use crate::ruv::error::Result;

/// Trait for text embedding providers
pub trait EmbeddingProvider: Send + Sync {
    /// Generate embedding vector for the given text
    fn embed(&self, text: &str) -> Result<Vec<f32>>;

    /// Get the dimensionality of embeddings produced by this provider
    fn dimensions(&self) -> usize;

    /// Get a description of this provider (for logging/debugging)
    fn name(&self) -> &str;
}

/// Hash-based embedding provider (placeholder, not semantic)
///
/// ⚠️ **WARNING**: This does NOT produce semantic embeddings!
/// - "dog" and "cat" will NOT be similar
/// - "dog" and "god" WILL be similar (same characters)
///
/// Use this only for testing or when semantic similarity is not required.
#[derive(Debug, Clone)]
pub struct HashEmbedding {
    dimensions: usize,
}

impl HashEmbedding {
    /// Create a new hash-based embedding provider
    pub fn new(dimensions: usize) -> Self {
        Self { dimensions }
    }
}

impl EmbeddingProvider for HashEmbedding {
    fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let mut embedding = vec![0.0; self.dimensions];
        let bytes = text.as_bytes();

        for (i, byte) in bytes.iter().enumerate() {
            embedding[i % self.dimensions] += (*byte as f32) / 255.0;
        }

        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for val in &mut embedding {
                *val /= norm;
            }
        }

        Ok(embedding)
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn name(&self) -> &str {
        "HashEmbedding (placeholder)"
    }
}

/// ONNX-based embedding provider using tract inference
///
/// Provides real semantic embeddings using sentence-transformers models
/// exported to ONNX format (e.g., all-MiniLM-L6-v2).
///
/// Requires feature flag: `onnx-embeddings`
///
/// # Example
/// ```rust,ignore
/// use ferro_mind::ruv::embeddings::{OnnxEmbedding, EmbeddingProvider};
///
/// let embedder = OnnxEmbedding::from_path("assets/model.onnx", "assets/tokenizer.json")?;
/// let embedding = embedder.embed("hello world")?;
/// assert_eq!(embedding.len(), 384);  // MiniLM-L6-v2 dimension
/// ```
#[cfg(feature = "onnx-embeddings")]
pub struct OnnxEmbedding {
    model_bytes: Vec<u8>,
    tokenizer: tokenizers::Tokenizer,
    dimensions: usize,
    max_length: usize,
}

#[cfg(feature = "onnx-embeddings")]
impl OnnxEmbedding {
    /// Load ONNX model and tokenizer from files
    ///
    /// # Arguments
    /// * `model_path` - Path to ONNX model file (e.g., "assets/model.onnx")
    /// * `tokenizer_path` - Path to tokenizer.json file
    ///
    /// # Returns
    /// OnnxEmbedding instance ready for inference
    pub fn from_path(model_path: &str, tokenizer_path: &str) -> Result<Self> {
        use std::fs;

        // Read model bytes (we'll parse on each embed for thread safety)
        let model_bytes = fs::read(model_path)
            .map_err(|e| crate::ruv::error::RuvError::ModelError(e.to_string()))?;

        // Load the tokenizer
        let tokenizer = tokenizers::Tokenizer::from_file(tokenizer_path)
            .map_err(|e| crate::ruv::error::RuvError::InferenceError(e.to_string()))?;

        Ok(Self {
            model_bytes,
            tokenizer,
            dimensions: 384,       // MiniLM-L6-v2 dimension
            max_length: 512,       // BERT max sequence length
        })
    }

    /// Load from the default asset paths
    pub fn from_default_assets() -> Result<Self> {
        Self::from_path(
            "ferro-mind/assets/model.onnx",
            "ferro-mind/assets/tokenizer.json",
        )
    }

    /// Tokenize text and prepare input tensors
    fn tokenize(&self, text: &str) -> Result<(Vec<i64>, Vec<i64>)> {
        let encoding = self.tokenizer
            .encode(text, true)
            .map_err(|e| crate::ruv::error::RuvError::InferenceError(e.to_string()))?;

        let ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = encoding.get_attention_mask().iter().map(|&m| m as i64).collect();

        // Pad or truncate to max_length
        let mut input_ids = ids;
        let mut mask = attention_mask;

        if input_ids.len() > self.max_length {
            input_ids.truncate(self.max_length);
            mask.truncate(self.max_length);
        } else {
            let pad_length = self.max_length - input_ids.len();
            input_ids.extend(vec![0i64; pad_length]);
            mask.extend(vec![0i64; pad_length]);
        }

        Ok((input_ids, mask))
    }

    /// Mean pooling over token embeddings
    fn mean_pooling(&self, embeddings: &[f32], attention_mask: &[i64]) -> Vec<f32> {
        let seq_len = self.max_length;
        let hidden_size = self.dimensions;

        let mut pooled = vec![0.0f32; hidden_size];
        let mut mask_sum = 0.0f32;

        for i in 0..seq_len {
            if attention_mask[i] > 0 {
                mask_sum += 1.0;
                for j in 0..hidden_size {
                    pooled[j] += embeddings[i * hidden_size + j];
                }
            }
        }

        // Normalize
        if mask_sum > 0.0 {
            for val in &mut pooled {
                *val /= mask_sum;
            }
        }

        // L2 normalize
        let norm: f32 = pooled.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for val in &mut pooled {
                *val /= norm;
            }
        }

        pooled
    }
}

#[cfg(feature = "onnx-embeddings")]
impl EmbeddingProvider for OnnxEmbedding {
    fn embed(&self, text: &str) -> Result<Vec<f32>> {
        use tract_onnx::prelude::*;
        use tract_onnx::onnx;
        use std::io::Cursor;

        // Tokenize input
        let (input_ids, attention_mask) = self.tokenize(text)?;

        // Create input tensors (shape: [1, seq_len])
        let shape = tract_ndarray::IxDyn(&[1, self.max_length]);

        let input_ids_tensor: Tensor = tract_ndarray::ArrayD::from_shape_vec(
            shape.clone(),
            input_ids.clone(),
        ).map_err(|e| crate::ruv::error::RuvError::ShapeError(e.to_string()))?.into();

        let attention_tensor: Tensor = tract_ndarray::ArrayD::from_shape_vec(
            shape.clone(),
            attention_mask.clone(),
        ).map_err(|e| crate::ruv::error::RuvError::ShapeError(e.to_string()))?.into();

        let token_type_ids: Vec<i64> = vec![0i64; self.max_length];
        let token_type_tensor: Tensor = tract_ndarray::ArrayD::from_shape_vec(
            shape,
            token_type_ids,
        ).map_err(|e| crate::ruv::error::RuvError::ShapeError(e.to_string()))?.into();

        // Load and run model (parsing on each call for thread safety)
        let model = onnx()
            .model_for_read(&mut Cursor::new(&self.model_bytes))
            .map_err(|e: TractError| crate::ruv::error::RuvError::ModelError(e.to_string()))?
            .into_optimized()
            .map_err(|e: TractError| crate::ruv::error::RuvError::ModelError(e.to_string()))?
            .into_runnable()
            .map_err(|e: TractError| crate::ruv::error::RuvError::ModelError(e.to_string()))?;

        // Run inference
        let result = model.run(tvec![
            input_ids_tensor.into(),
            attention_tensor.into(),
            token_type_tensor.into(),
        ]).map_err(|e: TractError| crate::ruv::error::RuvError::InferenceError(e.to_string()))?;

        // Extract output embeddings (shape: [1, seq_len, hidden_size])
        let output = result[0]
            .to_array_view::<f32>()
            .map_err(|e: TractError| crate::ruv::error::RuvError::InferenceError(e.to_string()))?;
        let embeddings: Vec<f32> = output.iter().copied().collect();

        // Mean pooling
        let pooled = self.mean_pooling(&embeddings, &attention_mask);

        Ok(pooled)
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn name(&self) -> &str {
        "OnnxEmbedding (MiniLM-L6-v2)"
    }
}

#[cfg(feature = "onnx-embeddings")]
impl std::fmt::Debug for OnnxEmbedding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnnxEmbedding")
            .field("dimensions", &self.dimensions)
            .field("max_length", &self.max_length)
            .field("model_size", &self.model_bytes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_embedding_dimensions() {
        let embedder = HashEmbedding::new(384);
        assert_eq!(embedder.dimensions(), 384);
        assert_eq!(embedder.name(), "HashEmbedding (placeholder)");
    }

    #[test]
    fn test_hash_embedding_produces_normalized_vector() {
        let embedder = HashEmbedding::new(128);
        let embedding = embedder.embed("hello world").unwrap();

        // Check length
        assert_eq!(embedding.len(), 128);

        // Check L2 normalization (norm should be ~1.0)
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5);
    }

    #[test]
    fn test_hash_embedding_consistency() {
        let embedder = HashEmbedding::new(64);
        let e1 = embedder.embed("test string").unwrap();
        let e2 = embedder.embed("test string").unwrap();

        // Same input should produce same output
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_hash_embedding_different_inputs() {
        let embedder = HashEmbedding::new(64);
        let e1 = embedder.embed("hello").unwrap();
        let e2 = embedder.embed("world").unwrap();

        // Different inputs should produce different outputs
        assert_ne!(e1, e2);
    }

    #[cfg(feature = "onnx-embeddings")]
    #[test]
    fn test_onnx_embedding_dimensions() {
        // Skip if model files don't exist
        if !std::path::Path::new("ferro-mind/assets/model.onnx").exists() {
            eprintln!("Skipping ONNX test: model files not found");
            return;
        }

        let embedder = OnnxEmbedding::from_default_assets().unwrap();
        assert_eq!(embedder.dimensions(), 384);
        assert_eq!(embedder.name(), "OnnxEmbedding (MiniLM-L6-v2)");
    }

    #[cfg(feature = "onnx-embeddings")]
    #[test]
    fn test_onnx_embedding_produces_normalized_vector() {
        if !std::path::Path::new("ferro-mind/assets/model.onnx").exists() {
            eprintln!("Skipping ONNX test: model files not found");
            return;
        }

        let embedder = OnnxEmbedding::from_default_assets().unwrap();
        let embedding = embedder.embed("hello world").unwrap();

        // Check length
        assert_eq!(embedding.len(), 384);

        // Check L2 normalization
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-4);
    }

    #[cfg(feature = "onnx-embeddings")]
    #[test]
    fn test_onnx_embedding_semantic_similarity() {
        if !std::path::Path::new("ferro-mind/assets/model.onnx").exists() {
            eprintln!("Skipping ONNX test: model files not found");
            return;
        }

        let embedder = OnnxEmbedding::from_default_assets().unwrap();

        // Similar meanings should have high cosine similarity
        let e1 = embedder.embed("The cat sat on the mat").unwrap();
        let e2 = embedder.embed("A cat is sitting on a rug").unwrap();
        let e3 = embedder.embed("The stock market crashed today").unwrap();

        // Cosine similarity function
        fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
            let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
            let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
            let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
            dot / (norm_a * norm_b)
        }

        let sim_similar = cosine_similarity(&e1, &e2);
        let sim_different = cosine_similarity(&e1, &e3);

        // Similar sentences should have higher similarity than different ones
        assert!(sim_similar > sim_different,
            "Expected similar sentences to have higher similarity: {} vs {}",
            sim_similar, sim_different);

        // Similar sentences should have reasonably high similarity (>0.5)
        assert!(sim_similar > 0.5,
            "Expected similar sentences to have similarity >0.5, got {}", sim_similar);
    }
}
