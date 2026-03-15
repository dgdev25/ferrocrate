//! FerroCrate Test Framework
//!
//! Provides a unified testing infrastructure for all test categories:
//! - P0: Unit tests (fast, isolated, mocked)
//! - P1: Integration tests (real components, no external services)
//! - P2: E2E tests (full workflows, may use external services)
//! - P3: Property-based and security tests (fuzzing, vulnerability scanning)

pub mod assertions;
pub mod fixtures;
pub mod harness;
pub mod isolation;
pub mod metrics;
pub mod reporting;
pub mod runner;

// Re-export commonly used items
pub use assertions::*;
pub use fixtures::{Fixture, FixtureManager};
pub use harness::{TestHarness, TestResult, TestStatus};
pub use isolation::{ContainerGuard, NetworkGuard, TempDirGuard};
pub use metrics::{Metric, MetricsCollector};
pub use reporting::{Report, ReportGenerator, TestReport};
pub use runner::{TestRunner, TestSuite};
// Note: TestCategory is defined here in mod.rs, not re-exported from runner

/// Test priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// P0: Unit tests - fast, isolated, must pass for merge
    P0,
    /// P1: Integration tests - real components, must pass for merge
    P1,
    /// P2: E2E tests - full workflows, should pass for release
    P2,
    /// P3: Property/Security tests - nice to have, informational
    P3,
}

impl Priority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Priority::P0 => "P0",
            Priority::P1 => "P1",
            Priority::P2 => "P2",
            Priority::P3 => "P3",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Priority::P0 => "Unit tests - fast, isolated, must pass",
            Priority::P1 => "Integration tests - real components, must pass",
            Priority::P2 => "E2E tests - full workflows, should pass",
            Priority::P3 => "Property/Security tests - informational",
        }
    }
}

/// Test categories for organization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TestCategory {
    /// Core functionality tests
    Core,
    /// Container lifecycle tests
    ContainerLifecycle,
    /// Networking tests
    Networking,
    /// Storage/volume tests
    Storage,
    /// Compose/orchestration tests
    Compose,
    /// Security tests
    Security,
    /// Performance tests
    Performance,
    /// Compatibility tests
    Compatibility,
    /// API compatibility tests (Docker API)
    ApiCompat,
}

impl TestCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            TestCategory::Core => "core",
            TestCategory::ContainerLifecycle => "container",
            TestCategory::Networking => "networking",
            TestCategory::Storage => "storage",
            TestCategory::Compose => "compose",
            TestCategory::Security => "security",
            TestCategory::Performance => "performance",
            TestCategory::Compatibility => "compatibility",
            TestCategory::ApiCompat => "api-compat",
        }
    }
}
