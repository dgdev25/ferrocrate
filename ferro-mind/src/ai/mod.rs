//! AI and machine learning subsystems
//!
//! Provides intelligent automation, anomaly detection, model training, and optimization.

/// Autonomous AI agents for orchestration
pub mod agents;
/// Anomaly detection in container behavior
pub mod anomaly;
/// Audit logging and decision tracing
pub mod audit;
/// Telemetry collection for AI training data
pub mod collector;
/// Configuration management
pub mod config;
/// Decision explanation and transparency
pub mod explain;
/// GPU detection and management
pub mod gpu;
/// Machine learning and pattern recognition
pub mod learning;
/// Durable per-container token/memory metering
pub mod metering;
/// Online learning scheduler for incremental model updates
pub mod online_learner;
pub mod provenance;
/// Resource prediction and OOM prevention
pub mod resource;
/// Intelligent restart policies
pub mod restart;
/// Request routing optimization
pub mod routing;
/// Model training and export
pub mod training;
