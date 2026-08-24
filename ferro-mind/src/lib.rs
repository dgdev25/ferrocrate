#![allow(missing_docs)]
//! FerroCrate AI and Machine Learning module
//!
//! Provides AI orchestration, model training, inference, and intelligent resource prediction
//! capabilities for container management and optimization.

/// AI agents, training, and orchestration
#[cfg(any(not(test), target_os = "linux"))]
pub mod ai;
/// RuVector integration for semantic search and embeddings
#[cfg(any(not(test), target_os = "linux"))]
pub mod ruv;
/// WebAssembly integration and interface
#[cfg(any(not(test), target_os = "linux"))]
pub mod wasm;
