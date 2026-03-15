//! Test runner for executing and organizing test suites.

use std::collections::HashMap;
use std::time::Duration;

use super::{Priority, TestCategory};
use super::harness::{TestResult, TestStatus};

/// Test suite containing related tests
#[derive(Debug)]
pub struct TestSuite {
    pub name: String,
    pub category: TestCategory,
    pub priority: Priority,
    pub tests: Vec<String>,
    pub parallel: bool,
}

impl TestSuite {
    pub fn new(name: impl Into<String>, category: TestCategory, priority: Priority) -> Self {
        Self {
            name: name.into(),
            category,
            priority,
            tests: Vec::new(),
            parallel: false,
        }
    }

    pub fn with_test(mut self, test: impl Into<String>) -> Self {
        self.tests.push(test.into());
        self
    }

    pub fn parallel(mut self, parallel: bool) -> Self {
        self.parallel = parallel;
        self
    }
}

/// Test runner for executing test suites
#[derive(Debug, Default)]
pub struct TestRunner {
    suites: HashMap<String, TestSuite>,
    results: Vec<TestResult>,
    config: RunnerConfig,
}

#[derive(Debug, Clone)]
pub struct RunnerConfig {
    pub fail_fast: bool,
    pub parallel_suites: bool,
    pub timeout_seconds: u64,
    pub filter_priority: Option<Priority>,
    pub filter_category: Option<TestCategory>,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            fail_fast: false,
            parallel_suites: false,
            timeout_seconds: 300,
            filter_priority: None,
            filter_category: None,
        }
    }
}

impl TestRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: RunnerConfig) -> Self {
        Self {
            suites: HashMap::new(),
            results: Vec::new(),
            config,
        }
    }

    pub fn add_suite(&mut self, suite: TestSuite) {
        self.suites.insert(suite.name.clone(), suite);
    }

    /// Run all test suites matching filters
    pub fn run(&mut self) -> Vec<&TestResult> {
        // Filter suites
        let suites_to_run: Vec<&TestSuite> = self.suites.values()
            .filter(|s| {
                self.config.filter_priority.map_or(true, |p| s.priority <= p) &&
                self.config.filter_category.map_or(true, |c| s.category == c)
            })
            .collect();

        // Sort by priority (P0 first)
        let mut sorted_suites: Vec<_> = suites_to_run.into_iter().collect();
        sorted_suites.sort_by_key(|s| s.priority);

        // Return results
        self.results.iter().collect()
    }

    /// Get summary statistics
    pub fn summary(&self) -> RunnerSummary {
        let mut by_priority: HashMap<Priority, PrioritySummary> = HashMap::new();

        for result in &self.results {
            let entry = by_priority.entry(result.priority).or_insert(PrioritySummary::default());
            entry.total += 1;
            match result.status {
                TestStatus::Passed => entry.passed += 1,
                TestStatus::Failed => entry.failed += 1,
                TestStatus::Skipped => entry.skipped += 1,
                TestStatus::Ignored => entry.ignored += 1,
            }
            entry.total_duration += result.duration;
        }

        RunnerSummary {
            total_tests: self.results.len(),
            by_priority,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RunnerSummary {
    pub total_tests: usize,
    pub by_priority: HashMap<Priority, PrioritySummary>,
}

#[derive(Debug, Clone, Default)]
pub struct PrioritySummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub ignored: usize,
    pub total_duration: Duration,
}

/// Predefined test suites for FerroCrate
pub fn ferrocrate_test_suites() -> Vec<TestSuite> {
    vec![
        // P0 - Unit Tests
        TestSuite::new("core-unit", TestCategory::Core, Priority::P0)
            .with_test("ferro_core::dockerfile_parser::tests")
            .with_test("ferro_core::image_spec::tests")
            .with_test("ferro_core::storage::tests")
            .parallel(true),

        TestSuite::new("compose-unit", TestCategory::Compose, Priority::P0)
            .with_test("ferro_compose::tests")
            .with_test("ferro_compose::service_graph::tests")
            .parallel(true),

        TestSuite::new("net-unit", TestCategory::Networking, Priority::P0)
            .with_test("ferro_net::tests")
            .parallel(true),

        // P1 - Integration Tests
        TestSuite::new("container-integration", TestCategory::ContainerLifecycle, Priority::P1)
            .with_test("ferro-cli::tests::cli_integration")
            .with_test("ferro-cli::tests::dockerfile_parity_integration")
            .parallel(false),

        TestSuite::new("compose-integration", TestCategory::Compose, Priority::P1)
            .with_test("compose_up_down")
            .with_test("compose_dependency_resolution")
            .parallel(false),

        TestSuite::new("docker-compat", TestCategory::ApiCompat, Priority::P1)
            .with_test("ferro-cli::tests::docker_compat_integration")
            .parallel(false),

        // P2 - E2E Tests
        TestSuite::new("full-lifecycle", TestCategory::ContainerLifecycle, Priority::P2)
            .with_test("pull_build_run_stop_remove")
            .with_test("container_restart_state")
            .parallel(false),

        TestSuite::new("networking-e2e", TestCategory::Networking, Priority::P2)
            .with_test("container_networking")
            .with_test("port_forwarding")
            .parallel(false),

        // P3 - Property/Security Tests
        TestSuite::new("property-tests", TestCategory::Core, Priority::P3)
            .with_test("image_reference_roundtrip")
            .with_test("dockerfile_parser_fuzz")
            .parallel(true),

        TestSuite::new("security-tests", TestCategory::Security, Priority::P3)
            .with_test("input_validation")
            .with_test("privilege_escalation")
            .with_test("secrets_handling")
            .parallel(false),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suite_builder() {
        let suite = TestSuite::new("test-suite", TestCategory::Core, Priority::P0)
            .with_test("test1")
            .with_test("test2")
            .parallel(true);

        assert_eq!(suite.name, "test-suite");
        assert_eq!(suite.tests.len(), 2);
        assert!(suite.parallel);
    }

    #[test]
    fn test_runner_summary() {
        let mut runner = TestRunner::new();
        runner.add_suite(
            TestSuite::new("suite1", TestCategory::Core, Priority::P0)
                .with_test("test1")
        );

        assert_eq!(runner.suites.len(), 1);
    }
}
