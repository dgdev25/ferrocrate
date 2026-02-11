# FerroCrate Test Strategy

**Version:** 1.0 | **Date:** February 11, 2026 | **Owner:** Test Team

---

## 1. Executive Summary

This document defines the comprehensive testing strategy for FerroCrate, an AI-native container runtime written in Rust. Container runtimes are security-critical infrastructure where failures can lead to privilege escalation, data breaches, and system compromise. Our testing approach emphasizes:

1. **Security-first mindset** - Every attack surface tested
2. **OCI compliance** - Standard compatibility verification
3. **Performance rigor** - Sub-100ms startup guaranteed
4. **Fuzzing coverage** - Continuous input mutation testing
5. **Memory safety** - 100% coverage for unsafe blocks

---

## 2. Testing Pyramid

```
                    /\
                   /E2E\        <- OCI Compliance Suite (20-30 tests)
                  /------\
                 /Integration\  <- Container Operations (200+ tests)
                /--------------\
               /     Unit       \ <- Core Functions (1000+ tests)
              /------------------\
```

### 2.1 Unit Tests (Foundation)

- **Location:** `src/**/tests.rs` and `src/**/tests/**/*.rs`
- **Framework:** Native Rust `#[test]` and `#[cfg(test)]`
- **Coverage Target:** 80% line coverage overall
- **Execution Time:** <100ms total

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_create_with_valid_config() {
        let config = ContainerConfig::default();
        let result = Container::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_container_create_with_invalid_memory_limit() {
        let config = ContainerConfig {
            memory_limit: Some(0), // Invalid
            ..Default::default()
        };
        let result = Container::new(config);
        assert!(matches!(result, Err(ContainerError::InvalidMemoryLimit)));
    }
}
```

### 2.2 Integration Tests

- **Location:** `/tests/` directory
- **Framework:** Custom test harness with `testcontainers` patterns
- **Coverage Target:** All API endpoints and CLI commands
- **Execution Time:** <60 seconds total

### 2.3 End-to-End Tests

- **Location:** `/tests/e2e/` directory
- **Framework:** Custom OCI compliance harness
- **Coverage Target:** OCI spec conformance
- **Execution Time:** <5 minutes total

---

## 3. Test Categories

### 3.1 Unit Testing

| Component | Test Focus | Tools |
|-----------|------------|-------|
| `ferro-exec` | Namespace isolation, cgroup operations, process management | `#[test]`, `mockall` |
| `ferro-store` | Blake3 hashing, layer deduplication, content-addressable storage | `#[test]`, `tempfile` |
| `ferro-build` | Dockerfile parsing, build cache, layer creation | `#[test]`, `assert_cmd` |
| `ferro-net` | eBPF programs, network namespace setup, port mapping | `#[test]`, `netns-rs` |
| `ferro-mind` | WASM inference, resource prediction, anomaly detection | `#[test]`, `wasmtime` |
| `ferro-compose` | YAML parsing, dependency resolution, service ordering | `#[test]`, `serde_yaml` |

### 3.2 Integration Testing

| Category | Description | Environment |
|----------|-------------|-------------|
| Container Lifecycle | Create, start, stop, kill, remove, pause, unpause | Rootless namespace |
| Image Operations | Pull, push, build, tag, remove, prune | Local registry |
| Networking | Bridge, host, none, custom networks, DNS | Network namespaces |
| Storage | Volumes, bind mounts, tmpfs, overlayfs | Temp directories |
| Security | Rootless, seccomp, capabilities, apparmor | Unprivileged user |
| Compose | Multi-service deployment, scaling, dependencies | Docker-compose fixtures |

### 3.3 End-to-End Testing

| Category | Description | Validation |
|----------|-------------|------------|
| OCI Runtime Spec | Run official OCI runtime tests | oci-runtime-tool |
| OCI Image Spec | Build and verify OCI images | oci-image-tool |
| OCI Distribution Spec | Push/pull to registries | docker/distribution |
| Docker Compatibility | Run Docker test fixtures | docker-integration |
| Real Workloads | Run actual applications | nginx, postgres, redis |

### 3.4 Performance Testing

| Benchmark | Target | Measurement Method |
|-----------|--------|-------------------|
| Container startup (cold) | <100ms | `std::time::Instant` |
| Container startup (warm) | <50ms | Cached namespace |
| Image pull throughput | >500 MB/s | Network throughput |
| Idle memory (daemon) | <8 MB | `/proc/[pid]/status` |
| Per-container overhead | <2 MB | RSS delta |
| AI inference (WASM) | <1 ms | `Instant::now().elapsed()` |
| Build time | Within 15% of BuildKit | Side-by-side comparison |

### 3.5 Fuzzing

Continuous fuzzing with `cargo-fuzz` targeting:

| Target | Fuzzer | Corpus |
|--------|--------|--------|
| Image layer extraction | `libFuzzer` | Malformed tarballs |
| JSON manifest parsing | `libFuzzer` | Corrupted manifests |
| Dockerfile parsing | `libFuzzer` | Invalid syntax |
| Config file parsing | `libFuzzer` | Malformed TOML/YAML |
| Network packet handling | `libFuzzer` | Invalid eBPF input |
| Syscall handling | `libFuzzer` | Seccomp rule edge cases |

```rust
// fuzz/fuzz_target_1.rs
#![no_main]

use libfuzzer_sys::fuzz_target;
use ferro_store::layer::extract_layer;

fuzz_target!(|data: &[u8]| {
    // Fuzz layer extraction with arbitrary tarballs
    let _ = extract_layer(data);
});
```

### 3.6 Security Testing

| Attack Vector | Test Approach | Tooling |
|---------------|---------------|---------|
| Container escape | Privilege escalation attempts | Custom harness |
| Image vulnerability | Malicious image layers | Syft, Grype |
| Registry MITM | Certificate validation tests | mitmproxy |
| Input validation | Malformed API requests | fuzzing |
| cgroup escape | Resource limit bypass | Custom harness |
| Namespace escape | Isolation verification | nsenter tests |
| Seccomp bypass | Syscall filter circumvention | strace analysis |
| AppArmor bypass | MAC enforcement tests | aa-exec |

---

## 4. Test Infrastructure

### 4.1 Local Development

```bash
# Run all unit tests
cargo test --all

# Run with coverage
cargo tarpaulin --out Html --output-dir target/coverage

# Run specific test category
cargo test --test integration container_lifecycle

# Run benchmarks
cargo bench

# Run fuzzing (separate process)
cargo fuzz run fuzz_layer_extraction -- -max_total_time=3600
```

### 4.2 CI/CD Pipeline

```yaml
# .github/workflows/test.yml
name: Test Suite

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo test --all --no-fail-fast
      - run: cargo tarpaulin --out Xml

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v4
      - run: sudo ./scripts/setup-integration-env.sh
      - run: cargo test --test '*' -- --test-threads=4

  security-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v4
      - run: cargo audit
      - run: ./scripts/security-scan.sh

  fuzzing:
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v4
      - run: cargo fuzz run fuzz_layer_extraction -- -max_total_time=300

  oci-compliance:
    runs-on: ubuntu-latest
    needs: integration-tests
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/oci-runtime-tests.sh
      - run: ./scripts/oci-image-tests.sh
```

### 4.3 Test Fixtures

```
tests/
├── fixtures/
│   ├── images/           # Small test images
│   │   ├── alpine.tar
│   │   ├── busybox.tar
│   │   └── nginx.tar
│   ├── dockerfiles/      # Dockerfile test cases
│   │   ├── simple.Dockerfile
│   │   ├── multi-stage.Dockerfile
│   │   └── edge-cases.Dockerfile
│   ├── compose/          # Compose file test cases
│   │   ├── basic.yml
│   │   ├── with-dependencies.yml
│   │   └── with-networks.yml
│   └── security/         # Security test artifacts
│       ├── malicious.tar
│       ├── path-traversal.tar
│       └── setuid-binary.tar
├── integration/
│   ├── container_lifecycle.rs
│   ├── image_operations.rs
│   ├── networking.rs
│   └── security.rs
└── e2e/
    ├── oci_runtime_test.rs
    ├── oci_image_test.rs
    └── docker_compat_test.rs
```

---

## 5. Coverage Requirements

### 5.1 Line Coverage

| Component | Minimum | Target |
|-----------|---------|--------|
| `ferro-exec` | 80% | 90% |
| `ferro-store` | 80% | 85% |
| `ferro-build` | 80% | 85% |
| `ferro-net` | 75% | 85% |
| `ferro-mind` | 80% | 90% |
| `ferro-compose` | 80% | 85% |
| **Overall** | **80%** | **85%** |

### 5.2 Unsafe Block Coverage

**CRITICAL: 100% coverage required for all `unsafe` blocks.**

```rust
// Every unsafe block must have dedicated tests
#[cfg(test)]
mod unsafe_tests {
    use super::*;

    #[test]
    fn test_raw_syscall_error_handling() {
        // unsafe { ... } must be tested for all error paths
        let result = unsafe { raw_mount_syscall(/* invalid args */) };
        assert!(result.is_err());
    }
}
```

### 5.3 Branch Coverage

- Minimum 75% branch coverage
- All error paths must be exercised
- All `match` arms must be covered

---

## 6. Security Test Plan

### 6.1 Attack Surface Analysis

```
┌─────────────────────────────────────────────────────────────┐
│                     FERROCRATE ATTACK SURFACE               │
├─────────────────────────────────────────────────────────────┤
│  Input Vectors:                                             │
│  ├── Container images (tarballs, manifests, configs)        │
│  ├── Dockerfiles (user-provided build instructions)         │
│  ├── CLI arguments (command injection risk)                 │
│  ├── API requests (malformed JSON, injection)               │
│  ├── Registry responses (MITM, malicious registries)        │
│  └── Network packets (container traffic)                    │
├─────────────────────────────────────────────────────────────┤
│  Privilege Boundaries:                                      │
│  ├── User namespace (rootless -> unprivileged)              │
│  ├── Network namespace (container isolation)                │
│  ├── PID namespace (process isolation)                      │
│  ├── Mount namespace (filesystem isolation)                 │
│  └── cgroup (resource limits)                               │
├─────────────────────────────────────────────────────────────┤
│  Sensitive Operations:                                      │
│  ├── Filesystem writes (image layers, volumes)              │
│  ├── Network operations (port binding, iptables)            │
│  ├── Process execution (container entrypoint)               │
│  └── Syscall handling (seccomp filtering)                   │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Security Test Cases

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| SEC-001 | Rootless enforcement | Run container without root | Container runs as unprivileged user |
| SEC-002 | Namespace isolation | Process in container cannot see host PIDs | Only container PIDs visible |
| SEC-003 | Network isolation | Container cannot access host network | Separate network namespace |
| SEC-004 | Seccomp enforcement | Blocked syscall returns error | EPERM returned |
| SEC-005 | Capability dropping | Dropped capabilities unavailable | Operation fails |
| SEC-006 | Path traversal | Malicious path in image | Path normalized/rejected |
| SEC-007 | Setuid stripping | Setuid binaries in image | Bits stripped or container fails |
| SEC-008 | No-new-privileges | setuid binary cannot escalate | EPERM returned |
| SEC-009 | cgroup enforcement | Memory limit exceeded | OOM kill, not host OOM |
| SEC-010 | Image signature | Unsigned image rejected | Pull fails with error |
| SEC-011 | Registry TLS | Self-signed cert rejected | Connection fails |
| SEC-012 | Input sanitization | Malformed JSON rejected | Parse error returned |

### 6.3 Continuous Security Testing

- **Daily:** `cargo audit` for dependency CVEs
- **Daily:** Fuzzing campaigns run for 1 hour
- **Weekly:** Full security regression suite
- **Per-release:** Third-party penetration test

---

## 7. Performance Test Plan

### 7.1 Benchmark Suite

```rust
// benches/container_bench.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_container_startup(c: &mut Criterion) {
    let runtime = FerroRuntime::new();

    c.bench_function("container_startup_cold", |b| {
        b.iter(|| {
            let container = runtime.create_container(black_box(ContainerConfig::default()));
            container.start();
            container.kill();
            container.remove();
        });
    });

    c.bench_function("container_startup_warm", |b| {
        // Pre-warm namespace cache
        runtime.warm_namespace_cache();

        b.iter(|| {
            let container = runtime.create_container(black_box(ContainerConfig::default()));
            container.start();
            container.kill();
            container.remove();
        });
    });
}

criterion_group!(benches, bench_container_startup);
criterion_main!(benches);
```

### 7.2 Performance Regression Detection

- Benchmarks run on every PR
- Regression threshold: 10% slowdown triggers review
- Baseline comparisons against main branch
- Historical trend tracking in CI dashboard

---

## 8. Test Data Management

### 8.1 Test Images

| Image | Size | Purpose |
|-------|------|---------|
| `alpine:latest` | 5MB | Minimal container test |
| `busybox:latest` | 1MB | Basic functionality |
| `nginx:alpine` | 25MB | Web server test |
| `postgres:15-alpine` | 80MB | Database test |
| `node:18-alpine` | 170MB | Application test |
| `malicious-test` | 5MB | Security test fixture |

### 8.2 Test Registry

Local registry for integration tests:

```bash
# Start test registry
docker run -d -p 5000:5000 --name test-registry registry:2

# Push test images
./scripts/push-test-images.sh localhost:5000
```

---

## 9. Reporting and Metrics

### 9.1 Test Reports

- **Unit Tests:** JUnit XML for CI integration
- **Coverage:** HTML report with line-by-line coverage
- **Performance:** Criterion HTML reports
- **Security:** SARIF format for GitHub Security

### 9.2 Key Metrics

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| Test pass rate | 100% | <100% |
| Line coverage | 80% | <75% |
| Unsafe coverage | 100% | <100% |
| Benchmark regression | 0% | >10% |
| Fuzzing crashes | 0 | >0 |
| Security vulnerabilities | 0 critical | >0 critical |

---

## 10. Appendices

### A. Test Command Reference

```bash
# Run all tests
make test

# Run with verbose output
cargo test -- --nocapture

# Run specific test by name
cargo test test_container_create

# Run tests matching pattern
cargo test "container_lifecycle"

# Run ignored tests
cargo test -- --ignored

# Generate coverage report
make coverage

# Run benchmarks
make bench

# Run fuzzing
make fuzz
```

### B. Test Environment Setup

```bash
# Install test dependencies
./scripts/install-test-deps.sh

# Configure rootless environment
./scripts/setup-rootless.sh

# Start test registry
./scripts/start-test-registry.sh
```

### C. CI/CD Integration

See `.github/workflows/test.yml` for full pipeline configuration.

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-11 | Test Team | Initial version |
