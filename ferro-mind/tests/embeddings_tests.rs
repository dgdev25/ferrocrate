//! Tests for embedding providers

use ferro_mind::ruv::embeddings::{EmbeddingProvider, HashEmbedding};

#[cfg(feature = "onnx-embeddings")]
use ferro_mind::ruv::embeddings::OnnxEmbedding;

/// Test that HashEmbedding produces normalized vectors
#[test]
fn test_hash_embedding_normalized() {
    let embedder = HashEmbedding::new(128);

    let embedding = embedder.embed("hello world").expect("embed should work");

    // Check dimensions
    assert_eq!(embedding.len(), 128);

    // Check L2 norm is 1.0 (or very close)
    let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((norm - 1.0).abs() < 0.0001, "Embedding should be normalized");
}

/// Test that HashEmbedding produces consistent results
#[test]
fn test_hash_embedding_consistent() {
    let embedder = HashEmbedding::new(64);

    let embedding1 = embedder.embed("test string").expect("embed should work");
    let embedding2 = embedder.embed("test string").expect("embed should work");

    // Same input should produce same output
    assert_eq!(embedding1, embedding2);
}

/// Test that different inputs produce different embeddings
#[test]
fn test_hash_embedding_different_inputs() {
    let embedder = HashEmbedding::new(64);

    let embedding1 = embedder.embed("hello").expect("embed should work");
    let embedding2 = embedder.embed("world").expect("embed should work");

    // Different inputs should produce different outputs (hash-based)
    assert_ne!(embedding1, embedding2);
}

/// Test HashEmbedding dimensions method
#[test]
fn test_hash_embedding_dimensions() {
    let embedder = HashEmbedding::new(256);
    assert_eq!(embedder.dimensions(), 256);
}

/// Test HashEmbedding name method
#[test]
fn test_hash_embedding_name() {
    let embedder = HashEmbedding::new(128);
    assert!(embedder.name().contains("placeholder"));
}

// ONNX embedding tests - only run with feature flag and when model files exist
#[cfg(feature = "onnx-embeddings")]
mod onnx_tests {
    use super::*;
    use std::path::Path;

    fn model_exists() -> bool {
        Path::new("ferro-mind/assets/model.onnx").exists() &&
        Path::new("ferro-mind/assets/tokenizer.json").exists()
    }

    #[test]
    fn test_onnx_embedding_load() {
        if !model_exists() {
            eprintln!("Skipping test: model files not found");
            return;
        }

        let result = OnnxEmbedding::from_path(
            "ferro-mind/assets/model.onnx",
            "ferro-mind/assets/tokenizer.json",
        );

        assert!(result.is_ok(), "Failed to load ONNX model: {:?}", result.err());
    }

    #[test]
    fn test_onnx_embedding_dimensions() {
        if !model_exists() {
            eprintln!("Skipping test: model files not found");
            return;
        }

        let embedder = OnnxEmbedding::from_path(
            "ferro-mind/assets/model.onnx",
            "ferro-mind/assets/tokenizer.json",
        ).expect("Failed to load model");

        // MiniLM-L6-v2 produces 384-dimensional embeddings
        assert_eq!(embedder.dimensions(), 384);
    }

    #[test]
    fn test_onnx_embedding_basic() {
        if !model_exists() {
            eprintln!("Skipping test: model files not found");
            return;
        }

        let embedder = OnnxEmbedding::from_path(
            "ferro-mind/assets/model.onnx",
            "ferro-mind/assets/tokenizer.json",
        ).expect("Failed to load model");

        let embedding = embedder.embed("Hello, world!").expect("Embedding failed");

        // Check dimensions
        assert_eq!(embedding.len(), 384);

        // Check normalization
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.01, "Embedding should be approximately normalized");
    }

    #[test]
    fn test_onnx_embedding_semantic_similarity() {
        if !model_exists() {
            eprintln!("Skipping test: model files not found");
            return;
        }

        let embedder = OnnxEmbedding::from_path(
            "ferro-mind/assets/model.onnx",
            "ferro-mind/assets/tokenizer.json",
        ).expect("Failed to load model");

        // Similar sentences should have similar embeddings
        let embedding1 = embedder.embed("The cat sat on the mat").expect("Embedding failed");
        let embedding2 = embedder.embed("A cat is sitting on a mat").expect("Embedding failed");
        let embedding3 = embedder.embed("The stock market crashed yesterday").expect("Embedding failed");

        // Compute cosine similarities
        fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
            let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
            let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
            let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
            dot / (norm_a * norm_b)
        }

        let sim_similar = cosine_similarity(&embedding1, &embedding2);
        let sim_different = cosine_similarity(&embedding1, &embedding3);

        // Similar sentences should have higher similarity than different sentences
        assert!(
            sim_similar > sim_different,
            "Similar sentences should have higher cosine similarity: {} vs {}",
            sim_similar, sim_different
        );

        // The similar sentences should have reasonably high similarity
        assert!(sim_similar > 0.5, "Similar sentences should have similarity > 0.5, got {}", sim_similar);
    }

    #[test]
    fn test_onnx_embedding_name() {
        if !model_exists() {
            eprintln!("Skipping test: model files not found");
            return;
        }

        let embedder = OnnxEmbedding::from_path(
            "ferro-mind/assets/model.onnx",
            "ferro-mind/assets/tokenizer.json",
        ).expect("Failed to load model");

        assert!(embedder.name().contains("MiniLM"));
    }
}
