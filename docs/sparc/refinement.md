# FerroCrate Refinement Plan

**SPARC Phase:** Refinement (TDD Implementation)
**Version:** 1.0
**Date:** February 11, 2026
**Status:** Draft

---

## 1. TDD Strategy Overview

FerroCrate follows Test-Driven Development with three tiers of testing:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Test Pyramid                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                          ┌─────────────────┐                                │
│                          │   E2E Tests     │  ~50 tests                     │
│                          │   (Full Stack)  │  Slow, high confidence         │
│                          └────────┬────────┘                                │
│                      ┌───────────┴───────────┐                              │
│                      │   Integration Tests   │  ~200 tests                  │
│                      │   (Component Pairs)   │  Medium speed                 │
│                      └───────────┬───────────┘                              │
│              ┌───────────────────┴───────────────────┐                      │
│              │             Unit Tests                 │  ~1000 tests        │
│              │   (Functions, Methods, Algorithms)     │  Fast, isolated      │
│              └───────────────────────────────────────┘                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Test Categories

### 2.1 Unit Tests

**Purpose:** Test individual functions and methods in isolation

**Characteristics:**
- Fast execution (< 10ms per test)
- No external dependencies
- Mocked interfaces
- 100% coverage for unsafe blocks
- Property-based testing for algorithms

**Location:** `#[cfg(test)]` modules within each source file

**Example Structure:**
```rust
// crates/ferro-exec/src/container/create.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_container_id() {
        let id = generate_container_id();
        assert_eq!(id.len(), 64); // SHA-256 hex length
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_prepare_rootfs_with_missing_layer() {
        let manifest = create_test_manifest_with_missing_layer();
        let result = prepare_rootfs("test-id", &manifest);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::LayerNotFound(_)));
    }

    // Property-based test
    #[quickcheck]
    fn test_blake3_dedup_roundtrip(data: Vec<u8>) -> bool {
        let hash1 = blake3_hash(&data);
        let hash2 = blake3_hash(&data);
        hash1 == hash2
    }
}
```

### 2.2 Integration Tests

**Purpose:** Test component interactions and interfaces

**Characteristics:**
- Medium speed (100ms - 1s per test)
- Real component interactions
- Minimal mocking
- Tests trait implementations
- Tests error propagation

**Location:** `tests/integration/` directory

**Example Structure:**
```
tests/integration/
├── container_lifecycle.rs    # ferro-exec + ferro-store integration
├── image_pull.rs             # ferro-store + registry mock
├── network_setup.rs          # ferro-net + ferro-exec integration
├── build_workflow.rs         # ferro-build + ferro-exec + ferro-store
├── compose_up.rs             # All components together
└── ai_prediction.rs          # ferro-mind + ferro-exec integration
```

**Example Test:**
```rust
// tests/integration/container_lifecycle.rs

use ferro_exec::{ContainerRuntime, ContainerConfig};
use ferro_store::{ImageStore, PullOptions};
use tempfile::TempDir;

#[tokio::test]
async fn test_container_full_lifecycle() {
    // Setup
    let temp_dir = TempDir::new().unwrap();
    let store = ImageStore::new(temp_dir.path()).await.unwrap();
    let runtime = ContainerRuntime::new(Default::default()).unwrap();

    // Pull image
    let image_id = store.pull("alpine:latest", PullOptions::default()).await.unwrap();

    // Create container
    let config = ContainerConfig {
        image: image_id,
        cmd: vec!["echo".to_string(), "hello".to_string()],
        ..Default::default()
    };
    let container_id = runtime.create(config).unwrap();

    // Start container
    let pid = runtime.start(&container_id).unwrap();
    assert!(pid > 0);

    // Wait for completion
    let exit_status = runtime.wait(&container_id).await.unwrap();
    assert_eq!(exit_status.code, Some(0));

    // Remove container
    runtime.remove(&container_id, false).unwrap();
}
```

### 2.3 End-to-End Tests

**Purpose:** Test complete user workflows through the CLI

**Characteristics:**
- Slow (1s - 30s per test)
- Full system test
- Real network (when needed)
- Tests CLI interface
- Tests error messages

**Location:** `tests/e2e/` directory

**Example Structure:**
```
tests/e2e/
├── cli_run_test.rs           # ferrocrate run tests
├── cli_build_test.rs         # ferrocrate build tests
├── cli_compose_test.rs       # ferrocrate compose tests
├── cli_network_test.rs       # Network command tests
├── cli_migrate_test.rs       # Migration from Docker
└── common/
    └── fixtures.rs           # Test fixtures and helpers
```

**Example Test:**
```rust
// tests/e2e/cli_run_test.rs

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_run_alpine_echo() {
    let mut cmd = Command::cargo_bin("ferrocrate").unwrap();
    cmd.args(["run", "--rm", "alpine", "echo", "hello"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("hello"));
}

#[test]
fn test_run_with_env() {
    let mut cmd = Command::cargo_bin("ferrocrate").unwrap();
    cmd.args(["run", "--rm", "-e", "MY_VAR=test", "alpine", "printenv", "MY_VAR"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("test"));
}

#[test]
fn test_run_port_mapping() {
    let mut cmd = Command::cargo_bin("ferrocrate").unwrap();
    cmd.args(["run", "-d", "-p", "8080:80", "--name", "test-nginx", "nginx"]);

    cmd.assert().success();

    // Verify port is listening
    let mut curl = Command::new("curl");
    curl.args(["-s", "-o", "/dev/null", "-w", "%{http_code}", "http://localhost:8080"]);

    curl.assert()
        .stdout(predicate::str::contains("200").or(predicate::str::contains("403")));

    // Cleanup
    let mut cleanup = Command::cargo_bin("ferrocrate").unwrap();
    cleanup.args(["rm", "-f", "test-nginx"]);
    cleanup.assert().success();
}
```

---

## 3. Coverage Targets

### 3.1 Per-Component Coverage

| Component | Line Coverage | Branch Coverage | Notes |
|-----------|---------------|-----------------|-------|
| ferro-exec | 85% | 80% | Critical path, high coverage required |
| ferro-store | 80% | 75% | Data integrity critical |
| ferro-build | 75% | 70% | Complex instruction parsing |
| ferro-net | 80% | 75% | Security-sensitive |
| ferro-mind | 70% | 65% | AI logic has inherent uncertainty |
| ferro-compose | 75% | 70% | Complex dependency handling |
| **Unsafe blocks** | **100%** | **100%** | No exceptions |

### 3.2 Coverage by Feature Priority

```
Priority P0 Features:  90% line coverage minimum
Priority P1 Features:  80% line coverage minimum
Priority P2 Features:  70% line coverage minimum
Unsafe Code:           100% line coverage required
```

### 3.3 Coverage Measurement

```bash
# Generate coverage report
cargo tarpaulin --workspace --out Html --output-dir coverage/

# Check coverage thresholds
cargo tarpaulin --workspace --out Stdout | ./scripts/check_coverage.sh
```

---

## 4. Fuzzing Strategy

### 4.1 Targets for Fuzzing

FerroCrate uses fuzzing to find edge cases in parsing and unsafe code:

| Target | Fuzzer | Input Type | Priority |
|--------|--------|------------|----------|
| Dockerfile parser | cargo-fuzz | Random text | High |
| OCI manifest parser | cargo-fuzz | Random JSON | High |
| Tar extraction | cargo-fuzz | Random bytes | Critical |
| Blake3 verification | cargo-fuzz | Random bytes | Medium |
| eBPF program loading | libFuzzer | Random BPF bytecode | High |

### 4.2 Fuzzing Setup

```rust
// fuzz/fuzz_targets/fuzz_dockerfile.rs

#![no_main]
use libfuzzer_sys::fuzz_target;
use ferro_build::parser::dockerfile::parse;

fuzz_target!(|data: &[u8]| {
    // Should never panic, always return Ok or Err
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse(s);
    }
});
```

```rust
// fuzz/fuzz_targets/fuzz_tar_extraction.rs

#![no_main]
use libfuzzer_sys::fuzz_target;
use ferro_store::layer::extract_tar;

fuzz_target!(|data: &[u8]| {
    // Tar extraction should handle malformed input gracefully
    let cursor = std::io::Cursor::new(data);
    let result = extract_tar(cursor, "/tmp/fuzz-test");
    // Should never panic
    assert!(result.is_ok() || result.is_err());
});
```

### 4.3 Fuzzing Integration

```yaml
# .github/workflows/fuzz.yml
name: Fuzzing
on:
  schedule:
    - cron: '0 0 * * *'  # Daily fuzzing run
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz

      - name: Run fuzzing
        run: |
          cargo fuzz run fuzz_dockerfile -- -max_total_time=3600
          cargo fuzz run fuzz_tar_extraction -- -max_total_time=3600

      - name: Report crashes
        if: failure()
        run: |
          echo "Fuzzing found crashes!"
          ls -la fuzz/artifacts/
```

---

## 5. Test Implementation Order

### Phase 1: Core Runtime (Week 1-2)

```
1. ferro-exec unit tests
   ├── namespace/ (user.rs, pid.rs, net.rs, mnt.rs)
   ├── cgroup/ (v2.rs, memory.rs, cpu.rs)
   ├── rootfs/ (overlay.rs, pivot.rs)
   └── security/ (seccomp.rs, capabilities.rs)

2. ferro-exec integration tests
   ├── container creation with namespaces
   ├── container lifecycle (create, start, stop, remove)
   └── rootless execution
```

### Phase 2: Image Management (Week 3-4)

```
1. ferro-store unit tests
   ├── storage/cas.rs
   ├── storage/layer.rs
   ├── dedup/blake3.rs
   └── registry/auth.rs

2. ferro-store integration tests
   ├── image pull from mock registry
   ├── layer deduplication verification
   └── content-addressable storage integrity
```

### Phase 3: Networking (Week 5)

```
1. ferro-net unit tests
   ├── bridge/create.rs
   ├── veth/pair.rs
   └── ipam/allocator.rs

2. ferro-net integration tests
   ├── container-to-container networking
   ├── port forwarding
   └── DNS resolution
```

### Phase 4: Building (Week 6)

```
1. ferro-build unit tests
   ├── parser/dockerfile.rs
   ├── builder/stage.rs
   └── snapshot/diff.rs

2. ferro-build integration tests
   ├── Dockerfile parsing and execution
   ├── multi-stage builds
   └── build cache effectiveness
```

### Phase 5: AI Layer (Week 7)

```
1. ferro-mind unit tests
   ├── predictor/features.rs
   ├── predictor/wasm.rs
   └── diagnosis/oom.rs

2. ferro-mind integration tests
   ├── resource prediction accuracy
   ├── intelligent restart decisions
   └── anomaly detection
```

### Phase 6: Compose (Week 8)

```
1. ferro-compose unit tests
   ├── parser/compose.rs
   └── dependency/graph.rs

2. ferro-compose integration tests
   ├── docker-compose.yml parsing
   ├── service dependency ordering
   └── multi-container networking
```

### Phase 7: E2E Tests (Week 9-10)

```
1. CLI tests
   ├── run command
   ├── build command
   ├── compose command
   └── network command

2. Migration tests
   └── docker-to-ferrocrate migration
```

---

## 6. Testing Infrastructure

### 6.1 Test Harness

```rust
// tests/common/harness.rs

use std::sync::Arc;
use tempfile::TempDir;
use ferro_exec::ContainerRuntime;
use ferro_store::ImageStore;
use ferro_net::NetworkManager;

/// Test harness for integration tests
pub struct TestHarness {
    pub temp_dir: TempDir,
    pub runtime: Arc<ContainerRuntime>,
    pub store: Arc<ImageStore>,
    pub network: Arc<NetworkManager>,
}

impl TestHarness {
    pub async fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        let store = Arc::new(
            ImageStore::new(temp_dir.path().join("store"))
                .await
                .expect("Failed to create store")
        );

        let runtime = Arc::new(
            ContainerRuntime::new(Default::default())
                .expect("Failed to create runtime")
        );

        let network = Arc::new(
            NetworkManager::new(Default::default())
                .expect("Failed to create network manager")
        );

        Self { temp_dir, runtime, store, network }
    }

    /// Pull a test image
    pub async fn pull_test_image(&self, name: &str) -> String {
        self.store
            .pull(name, PullOptions::default())
            .await
            .expect("Failed to pull test image")
    }

    /// Create and start a test container
    pub async fn run_test_container(&self, image: &str, cmd: Vec<&str>) -> String {
        let image_id = self.pull_test_image(image).await;

        let config = ContainerConfig {
            image: image_id.into(),
            cmd: cmd.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };

        let container_id = self.runtime.create(config).expect("Failed to create container");
        self.runtime.start(&container_id).expect("Failed to start container");

        container_id
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        // Cleanup all containers and images
        // ...
    }
}
```

### 6.2 Mock Registry

```rust
// tests/common/mock_registry.rs

use wiremock::{MockServer, Mock, ResponseTemplate};
use serde_json::json;

/// Mock OCI registry for testing
pub struct MockRegistry {
    server: MockServer,
}

impl MockRegistry {
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        Self { server }
    }

    pub fn url(&self) -> String {
        self.server.uri()
    }

    pub async fn mock_manifest(&self, name: &str, tag: &str) {
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!("/v2/{}/manifests/{}", name, tag)))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "sha256:config123",
                    "size": 1024
                },
                "layers": []
            })))
            .mount(&self.server)
            .await;
    }

    pub async fn mock_blob(&self, digest: &str, content: &[u8]) {
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!("/v2/blobs/{}", digest)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(content))
            .mount(&self.server)
            .await;
    }
}
```

### 6.3 CI/CD Test Pipeline

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1

      - name: Run unit tests
        run: cargo test --workspace --lib

      - name: Check coverage
        run: |
          cargo install cargo-tarpaulin
          cargo tarpaulin --workspace --out Stdout --fail-under 80

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1

      - name: Setup rootless environment
        run: |
          sudo sysctl -w kernel.unprivileged_userns_clone=1

      - name: Run integration tests
        run: cargo test --workspace --test '*' -- --test-threads=1

  e2e-tests:
    runs-on: ubuntu-latest
    needs: integration-tests
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1

      - name: Build binary
        run: cargo build --release

      - name: Run E2E tests
        run: cargo test --workspace --test 'e2e_*' -- --test-threads=1

  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1

      - name: Run cargo audit
        run: |
          cargo install cargo-audit
          cargo audit

      - name: Run cargo deny
        run: |
          cargo install cargo-deny
          cargo deny check
```

---

## 7. Unsafe Code Review Process

### 7.1 Unsafe Code Inventory

All unsafe blocks must be documented and tracked:

```rust
// SAFETY: This unsafe block is required because [reason].
// The following invariants are maintained:
// 1. [Invariant 1]
// 2. [Invariant 2]
// Tracking: https://github.com/ferrocrate/ferrocrate/issues/X
unsafe {
    // unsafe code
}
```

### 7.2 Unsafe Code Testing Requirements

```rust
// Every unsafe function must have:
// 1. Safety documentation
// 2. Unit tests for valid inputs
// 3. Unit tests for edge cases
// 4. Tests for each invariant

/// # Safety
///
/// This function is unsafe because it directly manipulates process namespaces.
///
/// ## Invariants
/// - The caller must ensure `pid` is a valid process ID
/// - The caller must have CAP_SYS_ADMIN or be in the same user namespace
/// - The file descriptor must be a valid namespace fd
///
/// ## Example
/// ```
/// # use ferro_exec::namespace::enter_namespace;
/// # use nix::unistd::Pid;
/// // SAFETY: pid is valid and we have necessary capabilities
/// unsafe {
///     enter_namespace(Pid::from_raw(1), NamespaceType::Net).unwrap();
/// }
/// ```
pub unsafe fn enter_namespace(pid: Pid, ns_type: NamespaceType) -> Result<()> {
    // Implementation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enter_namespace_valid_pid() {
        // Test with valid pid
    }

    #[test]
    fn test_enter_namespace_invalid_pid() {
        // Test with invalid pid - should return error
    }

    #[test]
    fn test_enter_namespace_permission_denied() {
        // Test without permissions - should return error
    }
}
```

---

## 8. Performance Benchmarks

### 8.1 Benchmark Categories

| Category | Benchmark | Target |
|----------|-----------|--------|
| Container | Startup time | < 100ms cold, < 50ms warm |
| Container | Memory overhead | < 2MB per container |
| Image | Pull throughput | > 500 MB/s |
| Image | Dedup ratio | > 40% storage savings |
| Network | Port forward latency | < 0.5ms |
| AI | WASM inference | < 1ms |

### 8.2 Benchmark Implementation

```rust
// benches/container_benchmark.rs

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use ferro_exec::{ContainerRuntime, ContainerConfig};
use ferro_store::ImageStore;

fn bench_container_startup(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (runtime, store) = rt.block_on(async {
        let store = ImageStore::new("/tmp/bench-store").await.unwrap();
        let runtime = ContainerRuntime::new(Default::default()).unwrap();
        (runtime, store)
    });

    // Warm cache
    rt.block_on(async {
        store.pull("alpine:latest", Default::default()).await.unwrap()
    });

    let mut group = c.benchmark_group("container_startup");

    group.bench_function("warm_cache", |b| {
        b.iter(|| {
            let config = ContainerConfig {
                image: "alpine:latest".into(),
                cmd: vec!["echo".into(), "test".into()],
                ..Default::default()
            };
            let id = runtime.create(config.clone()).unwrap();
            runtime.start(&id).unwrap();
            runtime.wait_sync(&id).unwrap();
            runtime.remove(&id, false).unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, bench_container_startup);
criterion_main!(benches);
```

---

## 9. Entry/Exit Criteria

### Phase 4: Refinement (Current)

**Entry Criteria:**
- [x] Architecture approved
- [x] Component interfaces defined
- [x] Test strategy documented

**Exit Criteria:**
- [ ] All unit tests passing (> 80% coverage)
- [ ] All integration tests passing
- [ ] E2E tests passing for P0 features
- [ ] Fuzzing complete with no crashes
- [ ] Performance benchmarks meeting targets
- [ ] Security audit passed
- [ ] Ready for integration testing

---

## Appendix A: Test Checklist Template

```markdown
## Feature: [Feature Name]

### Unit Tests
- [ ] Happy path test
- [ ] Error case test (invalid input)
- [ ] Error case test (permission denied)
- [ ] Edge case test (empty input)
- [ ] Edge case test (maximum input)
- [ ] Property-based test

### Integration Tests
- [ ] Component A + Component B interaction
- [ ] Error propagation test
- [ ] Resource cleanup test

### E2E Tests
- [ ] CLI command test
- [ ] User workflow test
- [ ] Error message test

### Security Tests
- [ ] Input validation test
- [ ] Permission check test
- [ ] Audit log test

### Performance Tests
- [ ] Latency benchmark
- [ ] Throughput benchmark
- [ ] Memory usage benchmark
```

---

## Appendix B: Debugging Test Failures

### Common Test Failure Patterns

| Failure Type | Likely Cause | Debugging Steps |
|-------------|--------------|-----------------|
| Namespace creation fails | Insufficient permissions | Check kernel.unprivileged_userns_clone |
| Cgroup creation fails | cgroup v2 not mounted | Mount cgroup2 filesystem |
| OverlayFS mount fails | Missing kernel module | modprobe overlay |
| eBPF load fails | Kernel too old | Check kernel version >= 5.10 |
| Port bind fails | Port already in use | Check for conflicting services |

### Debug Commands

```bash
# Run single test with verbose output
cargo test test_name -- --nocapture

# Run tests with logging
RUST_LOG=debug cargo test test_name -- --nocapture

# Check test coverage for specific file
cargo tarpaulin --specific src/container/create.rs

# Run fuzzing with specific seed
cargo fuzz run fuzz_target seed.file
```
