//! AI/ML tests for FerroCrate
//!
//! Tests for anomaly detection, restart policies, and vector memory.

use ferro_mind::ai::explain::DecisionTrace;
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

#[test]
fn explainability_trace_preserves_inputs_model_confidence_and_action() {
    let trace = DecisionTrace::new("trace-oom-1", "memory growth predicts OOM")
        .with_model("resource-oom-predictor", "runtime-v1")
        .with_decision("record-oom-prediction")
        .with_evidence("container_id", "demo")
        .with_evidence("current_memory_bytes", "768")
        .with_evidence("memory_limit_bytes", "1024")
        .with_evidence("confidence", "0.875");

    let encoded = serde_json::to_value(&trace).expect("decision trace should serialize");
    assert_eq!(encoded["model"], "resource-oom-predictor");
    assert_eq!(encoded["model_version"], "runtime-v1");
    assert_eq!(encoded["decision"], "record-oom-prediction");
    assert_eq!(encoded["evidence"]["container_id"], "demo");
    assert_eq!(encoded["evidence"]["confidence"], "0.875");
}

#[test]
fn explainability_trace_orders_evidence_for_reproducible_audit() {
    let trace = DecisionTrace::new("trace-repro", "restart decision")
        .with_evidence("zeta", "last")
        .with_evidence("alpha", "first");

    let json = serde_json::to_string(&trace).expect("decision trace should serialize");
    assert!(json.find("alpha").expect("alpha key") < json.find("zeta").expect("zeta key"));
}
