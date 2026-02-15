//! Tests for embedding providers

// Re-exports from ruvector-core
use ferro_mind::ruv::embeddings::{EmbeddingProvider, HashEmbedding};


/// Test that HashEmbedding (from ruvector-core) produces normalized vectors
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
    // ruvector-core uses "HashEmbedding" as name
    let name = embedder.name();
    assert!(name.contains("ash") || name.contains("Hash") || name.contains("hash"),
        "Name should indicate it's a hash embedding, got: {}", name);
}
