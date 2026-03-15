//! Test reporting infrastructure for generating test result reports.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::{Priority, TestCategory};
use super::harness::{TestStatus, TestResult};

/// Test report containing all results from a test run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestReport {
    /// Report timestamp
    pub timestamp: String,
    /// Git commit hash
    pub commit: String,
    /// Git branch
    pub branch: String,
    /// Rust version
    pub rust_version: String,
    /// Platform/OS
    pub platform: String,
    /// Total tests run
    pub total_tests: usize,
    /// Tests passed
    pub passed: usize,
    /// Tests failed
    pub failed: usize,
    /// Tests skipped
    pub skipped: usize,
    /// Tests ignored
    pub ignored: usize,
    /// Total duration
    pub duration_ms: u64,
    /// Results by priority
    pub by_priority: HashMap<String, PriorityStats>,
    /// Results by category
    pub by_category: HashMap<String, CategoryStats>,
    /// Individual test results
    pub results: Vec<TestResultJson>,
    /// Coverage summary
    pub coverage: Option<CoverageSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityStats {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryStats {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub avg_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResultJson {
    pub name: String,
    pub status: String,
    pub priority: String,
    pub category: String,
    pub duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub line_coverage: f64,
    pub branch_coverage: f64,
    pub function_coverage: f64,
    pub covered_lines: usize,
    pub total_lines: usize,
}

/// Report generator
pub struct ReportGenerator {
    results: Vec<TestResult>,
    start_time: Instant,
}

impl ReportGenerator {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            start_time: Instant::now(),
        }
    }

    /// Add a test result
    pub fn add_result(&mut self, result: TestResult) {
        self.results.push(result);
    }

    /// Generate the final report
    pub fn generate(&self) -> TestReport {
        let mut by_priority: HashMap<String, PriorityStats> = HashMap::new();
        let mut by_category: HashMap<String, CategoryStats> = HashMap::new();
        let mut total_passed = 0;
        let mut total_failed = 0;
        let mut total_skipped = 0;
        let mut total_ignored = 0;

        // Initialize priority stats
        for priority in [Priority::P0, Priority::P1, Priority::P2, Priority::P3] {
            by_priority.insert(
                priority.as_str().to_string(),
                PriorityStats { total: 0, passed: 0, failed: 0, skipped: 0 },
            );
        }

        // Process results
        for result in &self.results {
            let priority_key = result.priority.as_str().to_string();
            let category_key = result.category.as_str().to_string();

            if let Some(stats) = by_priority.get_mut(&priority_key) {
                stats.total += 1;
                match result.status {
                    TestStatus::Passed => { stats.passed += 1; total_passed += 1; }
                    TestStatus::Failed => { stats.failed += 1; total_failed += 1; }
                    TestStatus::Skipped => { stats.skipped += 1; total_skipped += 1; }
                    TestStatus::Ignored => { total_ignored += 1; }
                }
            }

            let category_entry = by_category.entry(category_key).or_insert(CategoryStats {
                total: 0, passed: 0, failed: 0, skipped: 0, avg_duration_ms: 0
            });
            category_entry.total += 1;
            category_entry.avg_duration_ms += result.duration.as_millis() as u64;
            match result.status {
                TestStatus::Passed => category_entry.passed += 1,
                TestStatus::Failed => category_entry.failed += 1,
                TestStatus::Skipped => category_entry.skipped += 1,
                TestStatus::Ignored => {}
            }
        }

        // Calculate averages for categories
        for stats in by_category.values_mut() {
            if stats.total > 0 {
                stats.avg_duration_ms /= stats.total as u64;
            }
        }

        let json_results: Vec<TestResultJson> = self.results.iter().map(|r| TestResultJson {
            name: r.name.clone(),
            status: r.status.as_str().to_string(),
            priority: r.priority.as_str().to_string(),
            category: r.category.as_str().to_string(),
            duration_ms: r.duration.as_millis() as u64,
            error: r.error.clone(),
        }).collect();

        TestReport {
            timestamp: chrono::Utc::now().to_rfc3339(),
            commit: get_git_commit(),
            branch: get_git_branch(),
            rust_version: get_rust_version(),
            platform: get_platform(),
            total_tests: self.results.len(),
            passed: total_passed,
            failed: total_failed,
            skipped: total_skipped,
            ignored: total_ignored,
            duration_ms: self.start_time.elapsed().as_millis() as u64,
            by_priority,
            by_category,
            results: json_results,
            coverage: None,
        }
    }

    /// Write report to JSON file
    pub fn write_json(&self, path: &Path) -> std::io::Result<()> {
        let report = self.generate();
        let json = serde_json::to_string_pretty(&report)?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())
    }

    /// Write report to HTML file
    pub fn write_html(&self, path: &Path) -> std::io::Result<()> {
        let report = self.generate();
        let html = generate_html_report(&report);
        let mut file = File::create(path)?;
        file.write_all(html.as_bytes())
    }

    /// Write JUnit XML for CI integration
    pub fn write_junit_xml(&self, path: &Path) -> std::io::Result<()> {
        let report = self.generate();
        let xml = generate_junit_xml(&report);
        let mut file = File::create(path)?;
        file.write_all(xml.as_bytes())
    }
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// Helper functions

fn get_git_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn get_git_branch() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn get_rust_version() -> String {
    std::process::Command::new("rustc")
        .args(["--version"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn get_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Generate HTML report
fn generate_html_report(report: &TestReport) -> String {
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FerroCrate Test Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .card h3 {{ margin: 0 0 10px 0; color: #666; font-size: 14px; }}
        .card .value {{ font-size: 32px; font-weight: bold; }}
        .passed {{ color: #22c55e; }}
        .failed {{ color: #ef4444; }}
        .skipped {{ color: #f59e0b; }}
        .table-container {{ background: white; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f9fafb; font-weight: 600; }}
        tr:hover {{ background: #f9fafb; }}
        .status-passed {{ color: #22c55e; font-weight: 600; }}
        .status-failed {{ color: #ef4444; font-weight: 600; }}
        .status-skipped {{ color: #f59e0b; font-weight: 600; }}
        .metadata {{ color: #666; font-size: 14px; margin-top: 10px; }}
        .priority-badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
        .P0 {{ background: #fef2f2; color: #991b1b; }}
        .P1 {{ background: #fff7ed; color: #9a3412; }}
        .P2 {{ background: #fefce8; color: #854d0e; }}
        .P3 {{ background: #f0fdf4; color: #166534; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>FerroCrate Test Report</h1>
            <div class="metadata">
                <span>Commit: {commit}</span> |
                <span>Branch: {branch}</span> |
                <span>Rust: {rust_version}</span> |
                <span>Platform: {platform}</span> |
                <span>Duration: {duration}s</span>
            </div>
        </div>

        <div class="summary">
            <div class="card">
                <h3>Total Tests</h3>
                <div class="value">{total_tests}</div>
            </div>
            <div class="card">
                <h3>Passed</h3>
                <div class="value passed">{passed}</div>
            </div>
            <div class="card">
                <h3>Failed</h3>
                <div class="value failed">{failed}</div>
            </div>
            <div class="card">
                <h3>Skipped</h3>
                <div class="value skipped">{skipped}</div>
            </div>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Test Name</th>
                        <th>Priority</th>
                        <th>Category</th>
                        <th>Duration</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>"#,
        commit = report.commit,
        branch = report.branch,
        rust_version = report.rust_version,
        platform = report.platform,
        duration = report.duration_ms as f64 / 1000.0,
        total_tests = report.total_tests,
        passed = report.passed,
        failed = report.failed,
        skipped = report.skipped,
        rows = report.results.iter().map(|r| format!(
            r#"<tr>
                <td class="status-{}">{}</td>
                <td>{}</td>
                <td><span class="priority-badge {}">{}</span></td>
                <td>{}</td>
                <td>{}ms</td>
            </tr>"#,
            r.status.to_lowercase(),
            r.status,
            r.name,
            r.priority,
            r.priority,
            r.category,
            r.duration_ms
        )).collect::<Vec<_>>().join("\n")
    )
}

/// Generate JUnit XML for CI integration
fn generate_junit_xml(report: &TestReport) -> String {
    let test_cases: Vec<String> = report.results.iter().map(|r| {
        let escaped_name = r.name.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
        if let Some(error) = &r.error {
            let escaped_error = error.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
            format!(
                r#"    <testcase name="{}" classname="{}" time="{}">
        <failure message="{}"/>
    </testcase>"#,
                escaped_name, r.category, r.duration_ms as f64 / 1000.0, escaped_error
            )
        } else {
            format!(
                r#"    <testcase name="{}" classname="{}" time="{}"/>"#,
                escaped_name, r.category, r.duration_ms as f64 / 1000.0
            )
        }
    }).collect();

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="ferrocrate" tests="{}" failures="{}" skipped="{}" time="{}">
{}
  </testsuite>
</testsuites>"#,
        report.total_tests,
        report.failed,
        report.skipped,
        report.duration_ms as f64 / 1000.0,
        test_cases.join("\n")
    )
}
