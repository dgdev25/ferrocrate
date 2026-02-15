// Embedding providers for semantic search.
//
// The runtime currently uses lightweight HashEmbedding from ruvector-core.
// Historical ONNX-based embedding support was removed from the default tree
// to reduce dependency risk and advisory surface.

pub use ruvector_core::{EmbeddingProvider, HashEmbedding};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_embedding_from_ruvector() {
        let embedder = HashEmbedding::new(384);
        assert_eq!(embedder.dimensions(), 384);
        assert!(embedder.name().contains("Hash") || embedder.name().contains("placeholder"));
    }

    #[test]
    fn test_hash_embedding_produces_normalized_vector() {
        let embedder = HashEmbedding::new(128);
        let embedding = embedder
            .embed("hello world")
            .expect("embed should succeed with valid input");

        assert_eq!(embedding.len(), 128);

        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5);
    }

    #[test]
    fn test_hash_embedding_consistency() {
        let embedder = HashEmbedding::new(64);
        let e1 = embedder.embed("test string").expect("embed should succeed");
        let e2 = embedder.embed("test string").expect("embed should succeed");

        assert_eq!(e1, e2);
    }

    #[test]
    fn test_hash_embedding_different_inputs() {
        let embedder = HashEmbedding::new(64);
        let e1 = embedder.embed("hello").expect("embed should succeed");
        let e2 = embedder.embed("world").expect("embed should succeed");

        assert_ne!(e1, e2);
    }
}
