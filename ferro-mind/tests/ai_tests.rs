//! AI/ML tests for FerroCrate
//!
//! Tests for anomaly detection, restart policies, and vector memory.

use ferro_mind::ai::learning::vector_memory::VectorMemory;
use ferro_mind::ruv::types::{DistanceMetric, VectorEntry, VectorId};
use serde_json::Value;
use std::collections::HashMap;

#[test]
fn vector_memory_insert_and_search() {
    let mut memory = VectorMemory::with_dimensions(3);

    // Insert some vectors
    memory.insert(VectorEntry {
        id: Some(VectorId::from("vec1")),
        vector: vec![1.0, 0.0, 0.0],
        metadata: Some(HashMap::new()),
    });
    memory.insert(VectorEntry {
        id: Some(VectorId::from("vec2")),
        vector: vec![0.0, 1.0, 0.0],
        metadata: Some(HashMap::new()),
    });
    memory.insert(VectorEntry {
        id: Some(VectorId::from("vec3")),
        vector: vec![1.0, 1.0, 0.0],
        metadata: Some(HashMap::new()),
    });

    // Search for closest to [1.0, 0.1, 0.0]
    let results = memory.search(&[1.0, 0.1, 0.0], 2, DistanceMetric::Euclidean);

    assert_eq!(results.len(), 2);
    // vec1 should be closest (distance ~0.1)
    assert_eq!(results[0].id.as_str(), "vec1");
}

#[test]
fn vector_memory_handles_empty() {
    let memory = VectorMemory::default();
    let results = memory.search(&[1.0, 2.0, 3.0], 5, DistanceMetric::Euclidean);
    assert!(results.is_empty());
}

#[test]
fn vector_memory_nan_handling_does_not_panic() {
    let mut memory = VectorMemory::default();

    // Insert a vector
    memory.insert(VectorEntry {
        id: Some(VectorId::from("normal")),
        vector: vec![1.0, 2.0, 3.0],
        metadata: Some(HashMap::new()),
    });

    // Search with a query that could produce NaN in distance calculations
    // This test verifies that the NaN handling in sort doesn't panic
    let query: Vec<f32> = vec![f32::NAN, 0.0, 0.0];
    let results = memory.search(&query, 1, DistanceMetric::Cosine);

    // Should not panic, may return empty or the entry depending on NaN handling
    // The key is that it doesn't crash
    let _ = results.len();
}

#[test]
fn vector_memory_cosine_distance() {
    let mut memory = VectorMemory::with_dimensions(3);

    memory.insert(VectorEntry {
        id: Some(VectorId::from("a")),
        vector: vec![1.0, 0.0, 0.0],
        metadata: Some(HashMap::new()),
    });
    memory.insert(VectorEntry {
        id: Some(VectorId::from("b")),
        vector: vec![0.9, 0.1, 0.0], // Similar direction to a
        metadata: Some(HashMap::new()),
    });
    memory.insert(VectorEntry {
        id: Some(VectorId::from("c")),
        vector: vec![0.0, 1.0, 0.0], // Orthogonal to a
        metadata: Some(HashMap::new()),
    });

    let results = memory.search(&[1.0, 0.0, 0.0], 2, DistanceMetric::Cosine);
    assert_eq!(results.len(), 2);
    // a should be first (distance 0), b should be second
    assert_eq!(results[0].id.as_str(), "a");
}

#[test]
fn vector_memory_metadata_preserved() {
    let mut memory = VectorMemory::default();
    let mut meta = HashMap::new();
    meta.insert("type".to_string(), Value::String("test".to_string()));

    memory.insert(VectorEntry {
        id: Some(VectorId::from("with-meta")),
        vector: vec![1.0, 0.0],
        metadata: Some(meta),
    });

    let results = memory.search(&[1.0, 0.0], 1, DistanceMetric::Euclidean);
    assert_eq!(results.len(), 1);
    if let Some(ref meta) = results[0].metadata {
        assert_eq!(meta.get("type"), Some(&Value::String("test".to_string())));
    } else {
        panic!("Expected metadata to be present");
    }
}
