//! RuVector integration for semantic search and vector embeddings
//!
//! Provides vector database operations, similarity search, and embedding management.

/// Distance metric computation
pub mod distance;
/// Vector embedding generation and management
pub mod embeddings;
/// Core vector types and data structures
pub mod types;
/// Error types for vector operations
pub mod error;
/// Vector deduplication
pub mod dedup;
/// RVF file format persistence layer
#[cfg(feature = "rvf-persistence")]
pub mod rvf_cache;
