// Embedding providers for semantic search
//
// Re-exports lightweight HashEmbedding from ruvector-core by default.
// Enable `onnx-embeddings` feature for semantic embeddings via ONNX/tract.
//
// # Feature Comparison
//
// | Provider         | Semantic | Size    | Latency  | Use Case              |
// |------------------|----------|---------|----------|----------------------|
// | HashEmbedding    | No       | 0 bytes | ~0.1ms   | Testing, prototyping |
// | OnnxEmbedding    | Yes      | 90MB    | ~10ms    | Production semantic  |

// Re-export lightweight embedding types from ruvector-core
pub use ruvector_core::{EmbeddingProvider, HashEmbedding};

#[cfg(feature = "onnx-embeddings")]
pub use onnx::OnnxEmbedding;

/// ONNX-based embedding provider using tract inference
///
/// Provides real semantic embeddings using sentence-transformers models
/// exported to ONNX format (e.g., all-MiniLM-L6-v2).
///
/// **NOTE**: Requires `onnx-embeddings` feature flag and model files.
/// Model files (~90MB) must be downloaded separately to `ferro-mind/assets/`.
#[cfg(feature = "onnx-embeddings")]
mod onnx {
    use ruvector_core::{EmbeddingProvider, RuvectorError, Result};
    use std::io::Cursor;

    /// ONNX-based embedding provider using tract inference
    pub struct OnnxEmbedding {
        model_bytes: Vec<u8>,
        tokenizer: tokenizers::Tokenizer,
        dimensions: usize,
        max_length: usize,
    }

    impl OnnxEmbedding {
        /// Load ONNX model and tokenizer from files
        ///
        /// # Arguments
        /// * `model_path` - Path to ONNX model file (e.g., "assets/model.onnx")
        /// * `tokenizer_path` - Path to tokenizer.json file
        pub fn from_path(model_path: &str, tokenizer_path: &str) -> Result<Self> {
            use std::fs;

            let model_bytes = fs::read(model_path)
                .map_err(|e| RuvectorError::ModelLoadError(e.to_string()))?;

            let tokenizer = tokenizers::Tokenizer::from_file(tokenizer_path)
                .map_err(|e| RuvectorError::ModelLoadError(e.to_string()))?;

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

        fn tokenize(&self, text: &str) -> Result<(Vec<i64>, Vec<i64>)> {
            let encoding = self.tokenizer
                .encode(text, true)
                .map_err(|e| RuvectorError::ModelInferenceError(e.to_string()))?;

            let ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
            let attention_mask: Vec<i64> = encoding.get_attention_mask().iter().map(|&m| m as i64).collect();

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

            if mask_sum > 0.0 {
                for val in &mut pooled {
                    *val /= mask_sum;
                }
            }

            let norm: f32 = pooled.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm > 0.0 {
                for val in &mut pooled {
                    *val /= norm;
                }
            }

            pooled
        }
    }

    impl EmbeddingProvider for OnnxEmbedding {
        fn embed(&self, text: &str) -> Result<Vec<f32>> {
            use tract_onnx::prelude::*;
            use tract_onnx::onnx;

            let (input_ids, attention_mask) = self.tokenize(text)?;

            let shape = tract_ndarray::IxDyn(&[1, self.max_length]);

            let input_ids_tensor: Tensor = tract_ndarray::ArrayD::from_shape_vec(
                shape.clone(),
                input_ids.clone(),
            ).map_err(|e| RuvectorError::ModelInferenceError(e.to_string()))?.into();

            let attention_tensor: Tensor = tract_ndarray::ArrayD::from_shape_vec(
                shape.clone(),
                attention_mask.clone(),
            ).map_err(|e| RuvectorError::ModelInferenceError(e.to_string()))?.into();

            let token_type_ids: Vec<i64> = vec![0i64; self.max_length];
            let token_type_tensor: Tensor = tract_ndarray::ArrayD::from_shape_vec(
                shape,
                token_type_ids,
            ).map_err(|e| RuvectorError::ModelInferenceError(e.to_string()))?.into();

            let model = onnx()
                .model_for_read(&mut Cursor::new(&self.model_bytes))
                .map_err(|e: TractError| RuvectorError::ModelLoadError(e.to_string()))?
                .into_optimized()
                .map_err(|e: TractError| RuvectorError::ModelLoadError(e.to_string()))?
                .into_runnable()
                .map_err(|e: TractError| RuvectorError::ModelLoadError(e.to_string()))?;

            let result = model.run(tvec![
                input_ids_tensor.into(),
                attention_tensor.into(),
                token_type_tensor.into(),
            ]).map_err(|e: TractError| RuvectorError::ModelInferenceError(e.to_string()))?;

            let output = result[0]
                .to_array_view::<f32>()
                .map_err(|e: TractError| RuvectorError::ModelInferenceError(e.to_string()))?;
            let embeddings: Vec<f32> = output.iter().copied().collect();

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

    impl std::fmt::Debug for OnnxEmbedding {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("OnnxEmbedding")
                .field("dimensions", &self.dimensions)
                .field("max_length", &self.max_length)
                .field("model_size", &self.model_bytes.len())
                .finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_embedding_from_ruvector() {
        let embedder = HashEmbedding::new(384);
        assert_eq!(embedder.dimensions(), 384);
        // ruvector-core's HashEmbedding uses "HashEmbedding (placeholder)"
        assert!(embedder.name().contains("Hash") || embedder.name().contains("placeholder"));
    }

    #[test]
    fn test_hash_embedding_produces_normalized_vector() {
        let embedder = HashEmbedding::new(128);
        let embedding = embedder.embed("hello world").unwrap();

        assert_eq!(embedding.len(), 128);

        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5);
    }

    #[test]
    fn test_hash_embedding_consistency() {
        let embedder = HashEmbedding::new(64);
        let e1 = embedder.embed("test string").unwrap();
        let e2 = embedder.embed("test string").unwrap();

        assert_eq!(e1, e2);
    }

    #[test]
    fn test_hash_embedding_different_inputs() {
        let embedder = HashEmbedding::new(64);
        let e1 = embedder.embed("hello").unwrap();
        let e2 = embedder.embed("world").unwrap();

        assert_ne!(e1, e2);
    }
}
