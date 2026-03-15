//! Test harness providing setup, teardown, and execution utilities.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::{Priority, TestCategory};

/// Test execution result
#[derive(Debug, Clone)]
pub struct TestResult {
    /// Test name
    pub name: String,
    /// Test status
    pub status: TestStatus,
    /// Duration
    pub duration: Duration,
    /// Priority level
    pub priority: Priority,
    /// Test category
    pub category: TestCategory,
    /// Error message if failed
    pub error: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Test status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestStatus {
    Passed,
    Failed,
    Skipped,
    Ignored,
}

impl TestStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TestStatus::Passed => "PASSED",
            TestStatus::Failed => "FAILED",
            TestStatus::Skipped => "SKIPPED",
            TestStatus::Ignored => "IGNORED",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            TestStatus::Passed => "✅",
            TestStatus::Failed => "❌",
            TestStatus::Skipped => "⏭️",
            TestStatus::Ignored => "⏸️",
        }
    }
}

/// Test harness for setup and teardown
pub struct TestHarness {
    /// Test name
    name: String,
    /// Priority level
    priority: Priority,
    /// Test category
    category: TestCategory,
    /// Temporary directory for test isolation
    temp_dir: Option<tempfile::TempDir>,
    /// Start time
    start_time: Option<Instant>,
    /// Cleanup functions
    cleanup: Vec<Box<dyn FnOnce() + Send>>,
}

impl TestHarness {
    /// Create a new test harness
    pub fn new(name: impl Into<String>, priority: Priority, category: TestCategory) -> Self {
        Self {
            name: name.into(),
            priority,
            category,
            temp_dir: None,
            start_time: None,
            cleanup: Vec::new(),
        }
    }

    /// Start the test harness (setup phase)
    pub fn start(&mut self) -> std::io::Result<()> {
        self.start_time = Some(Instant::now());
        self.temp_dir = Some(tempfile::tempdir()?);
        Ok(())
    }

    /// Get the temporary directory path
    pub fn temp_dir(&self) -> Option<&std::path::Path> {
        self.temp_dir.as_ref().map(|t| t.path())
    }

    /// Register a cleanup function
    pub fn register_cleanup<F: FnOnce() + Send + 'static>(&mut self, f: F) {
        self.cleanup.push(Box::new(f));
    }

    /// Finish the test and return result
    pub fn finish(self, status: TestStatus, error: Option<String>) -> TestResult {
        let duration = self.start_time
            .map(|s| s.elapsed())
            .unwrap_or_default();

        TestResult {
            name: self.name,
            status,
            duration,
            priority: self.priority,
            category: self.category,
            error,
            metadata: HashMap::new(),
        }
    }

    /// Run a test closure with automatic setup/teardown
    pub fn run<F>(mut self, f: F) -> TestResult
    where
        F: FnOnce(&Self) -> Result<(), String>,
    {
        if let Err(e) = self.start() {
            return self.finish(TestStatus::Failed, Some(format!("Setup failed: {}", e)));
        }

        let result = f(&self);
        let (status, error) = match result {
            Ok(()) => (TestStatus::Passed, None),
            Err(e) => (TestStatus::Failed, Some(e)),
        };

        self.finish(status, error)
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        // Run cleanup functions in reverse order
        while let Some(cleanup) = self.cleanup.pop() {
            cleanup();
        }
    }
}

/// Builder for creating test harnesses with common configurations
pub struct TestHarnessBuilder {
    name: String,
    priority: Priority,
    category: TestCategory,
    env: HashMap<String, String>,
    setup_fn: Option<Box<dyn FnMut(&mut TestHarness) -> Result<(), String> + Send>>,
}

impl TestHarnessBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            priority: Priority::P0,
            category: TestCategory::Core,
            env: HashMap::new(),
            setup_fn: None,
        }
    }

    pub fn priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    pub fn category(mut self, category: TestCategory) -> Self {
        self.category = category;
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> TestHarness {
        let mut harness = TestHarness::new(self.name, self.priority, self.category);
        // Apply environment if needed
        harness
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harness_basic() {
        let result = TestHarness::new("test_example", Priority::P0, TestCategory::Core)
            .run(|_| Ok(()));

        assert_eq!(result.status, TestStatus::Passed);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_harness_failure() {
        let result = TestHarness::new("test_failure", Priority::P0, TestCategory::Core)
            .run(|_| Err("Intentional failure".to_string()));

        assert_eq!(result.status, TestStatus::Failed);
        assert_eq!(result.error, Some("Intentional failure".to_string()));
    }

    #[test]
    fn test_harness_temp_dir() {
        let mut harness = TestHarness::new("test_temp", Priority::P0, TestCategory::Core);
        harness.start().expect("setup");

        let temp_path = harness.temp_dir().expect("temp dir");
        assert!(temp_path.exists());
    }
}
