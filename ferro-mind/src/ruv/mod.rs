//! RuVector integration for semantic search and vector embeddings
//!
//! Provides vector database operations, similarity search, and embedding management.

/// Vector deduplication
pub mod dedup;
/// Distance metric computation
pub mod distance;
/// Vector embedding generation and management
pub mod embeddings;
/// Error types for vector operations
pub mod error;
/// RVF file format persistence layer
#[cfg(feature = "rvf-persistence")]
pub mod rvf_cache;
/// Core vector types and data structures
pub mod types;
