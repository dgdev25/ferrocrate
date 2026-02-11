# Coverage Targets

**Version:** 1.0 | **Date:** February 11, 2026 | **Status:** Active

---

## Overview

This document defines the code coverage requirements for FerroCrate. Coverage targets are derived from the PRD requirement REL-05 and industry best practices for safety-critical infrastructure software.

---

## Summary of Coverage Requirements

| Level | Target | Rationale |
|-------|--------|-----------|
| Overall Line Coverage | 80% minimum | Industry standard for critical infrastructure |
| Unsafe Block Coverage | 100% required | Memory safety is non-negotiable |
| Branch Coverage | 75% minimum | Ensure all decision paths tested |
| Function Coverage | 80% minimum | All public APIs tested |
| OCI Spec Paths | 100% required | Compliance requirement |

---

## Component-Level Targets

### Core Components (P0)

| Component | Line Coverage | Branch Coverage | Unsafe Coverage | Notes |
|-----------|--------------|-----------------|-----------------|-------|
| `ferro-exec` | 85% | 80% | 100% | Container runtime core |
| `ferro-store` | 80% | 75% | 100% | Image storage |
| `ferro-build` | 80% | 75% | 100% | Build system |
| `ferro-net` | 80% | 75% | 100% | Networking |
| `ferro-compose` | 80% | 75% | 100% | Multi-container |

### Intelligence Components (P1)

| Component | Line Coverage | Branch Coverage | Unsafe Coverage | Notes |
|-----------|--------------|-----------------|-----------------|-------|
| `ferro-mind` | 85% | 80% | 100% | AI/ML layer |
| `ferro-predict` | 80% | 75% | 100% | Resource prediction |
| `ferro-anomaly` | 80% | 75% | 100% | Anomaly detection |

### CLI and Utilities

| Component | Line Coverage | Branch Coverage | Unsafe Coverage | Notes |
|-----------|--------------|-----------------|-----------------|-------|
| `ferro-cli` | 75% | 70% | 100% | Command-line interface |
| `ferro-utils` | 80% | 75% | 100% | Shared utilities |

---

## Unsafe Block Coverage Requirements

### Why 100%?

FerroCrate is written in Rust primarily for memory safety. However, container runtimes require `unsafe` blocks for:

1. **System calls** - Direct kernel interaction
2. **Namespace manipulation** - `clone()`, `unshare()`, `setns()`
3. **Cgroup operations** - Filesystem writes to cgroup paths
4. **Memory mapping** - `mmap()` for shared memory
5. **Foreign function interface** - C library bindings

Any bug in these blocks is a potential security vulnerability.

### Unsafe Block Testing Requirements

Every `unsafe` block MUST have:

1. **At least one positive test** - Verifies correct operation
2. **All error path tests** - Every `Err` path exercised
3. **Edge case tests** - Boundary conditions validated
4. **Fuzz tests where applicable** - Input mutation testing

### Example: Unsafe Block Test Coverage

```rust
// src/namespace.rs
pub unsafe fn enter_namespace(pid: u32, ns_type: NamespaceType) -> Result<()> {
    let path = format!("/proc/{}/ns/{}", pid, ns_type.as_str());
    let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
    if fd < 0 {
        return Err(Error::NamespaceOpen(errno::errno()));
    }
    let ret = libc::setns(fd, 0);
    libc::close(fd);
    if ret < 0 {
        return Err(Error::NamespaceEnter(errno::errno()));
    }
    Ok(())
}

// tests/namespace_tests.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enter_namespace_success() {
        // Test valid namespace entry
        let pid = std::process::id();
        let result = unsafe { enter_namespace(pid, NamespaceType::Net) };
        assert!(result.is_ok());
    }

    #[test]
    fn test_enter_namespace_invalid_pid() {
        // Test error path: non-existent PID
        let result = unsafe { enter_namespace(999999999, NamespaceType::Net) };
        assert!(matches!(result, Err(Error::NamespaceOpen(_))));
    }

    #[test]
    fn test_enter_namespace_permission_denied() {
        // Test error path: insufficient permissions
        // This test requires running as non-root
        if !is_root() {
            let result = unsafe { enter_namespace(1, NamespaceType::Net) };
            assert!(matches!(result, Err(Error::NamespaceOpen(_))));
        }
    }
}
```

---

## Coverage Exclusions

### Allowed Exclusions

The following code may be excluded from coverage calculations:

1. **Generated code** - Procedural macro outputs
2. **Dead code** - Code explicitly marked for future use
3. **Platform-specific code** - Conditional compilation for other platforms
4. **Panic paths** - Unreachable panic branches
5. **Debug/trace code** - Conditional debug logging

### Exclusion Documentation

All exclusions MUST be documented with:

```rust
// coverage:ignore - Platform-specific (Windows only)
#[cfg(target_os = "windows")]
fn windows_specific() { ... }

// coverage:ignore - Future feature, not yet implemented
fn planned_feature() {
    todo!("Implement in v2.0");
}
```

---

## Measuring Coverage

### Tools

```bash
# Primary: cargo-tarpaulin
cargo tarpaulin --out Html --output-dir target/coverage

# Alternative: cargo-llvm-cov (faster)
cargo llvm-cov --html --output-dir target/coverage

# For CI: Generate lcov format
cargo tarpaulin --out Lcov --output-dir target/coverage
```

### CI Integration

```yaml
# .github/workflows/coverage.yml
name: Coverage

on: [push, pull_request]

jobs:
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install tarpaulin
        run: cargo install cargo-tarpaulin

      - name: Generate coverage
        run: cargo tarpaulin --out Xml --output-dir coverage

      - name: Check coverage thresholds
        run: |
          python scripts/check_coverage.py coverage/cobertura.xml \
            --overall 80 \
            --unsafe 100 \
            --fail-under

      - name: Upload to codecov
        uses: codecov/codecov-action@v3
        with:
          files: coverage/cobertura.xml
```

### Coverage Report Review

Every PR MUST include:

1. **Coverage diff** - Change from baseline
2. **New code coverage** - Coverage of added lines
3. **Uncovered lines report** - Explanation for any uncovered code

---

## Coverage Gates

### Pull Request Requirements

| Check | Threshold | Enforcement |
|-------|-----------|-------------|
| Overall coverage | >= 80% | Blocking |
| New code coverage | >= 80% | Blocking |
| Unsafe block coverage | = 100% | Blocking |
| Coverage decrease | < 1% | Warning |
| Coverage decrease | >= 1% | Blocking |

### Merge Requirements

- All coverage gates must pass
- No uncovered unsafe blocks in new code
- Coverage trend must be stable or improving

---

## Coverage Reporting

### Dashboard Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| Line Coverage | % of lines executed | 80%+ |
| Branch Coverage | % of branches taken | 75%+ |
| Function Coverage | % of functions called | 80%+ |
| Unsafe Coverage | % of unsafe blocks covered | 100% |
| Cyclomatic Complexity | Average per function | < 15 |

### Report Locations

- **HTML Report:** `target/coverage/index.html`
- **LCOV:** `target/coverage/lcov.info`
- **XML (CI):** `target/coverage/cobertura.xml`

---

## Improving Coverage

### Priority Order

1. **Unsafe blocks** - Highest priority, 100% required
2. **OCI spec paths** - Compliance requirement
3. **Error handling paths** - Security critical
4. **Happy path** - Standard functionality
5. **Edge cases** - Robustness

### Coverage Improvement Process

1. Identify uncovered code via HTML report
2. Classify as: bug (missing test) or exclusion (document why)
3. For bugs: write tests
4. For exclusions: add `// coverage:ignore` with reason
5. Re-run coverage
6. Commit with "coverage:" prefix

---

## Enforcement

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Quick coverage check for changed files
CHANGED_FILES=$(git diff --name-only HEAD | grep '\.rs$')

if [ -n "$CHANGED_FILES" ]; then
    echo "Running coverage check on changed files..."

    # Check for new unsafe blocks without tests
    for file in $CHANGED_FILES; do
        if grep -q "unsafe" "$file"; then
            test_file="${file%.rs}_tests.rs"
            if [ ! -f "$test_file" ] && ! grep -q "#\[test\]" "$file"; then
                echo "WARNING: $file contains unsafe but no tests"
            fi
        fi
    done
fi
```

### CI Failure Messages

```
Coverage check failed:

- Overall coverage: 78.5% (required: 80%)
- Unsafe coverage: 95.2% (required: 100%)

Uncovered unsafe blocks:
  - src/namespace.rs:45 - enter_namespace()
  - src/cgroup.rs:102 - write_cgroup_file()

Please add tests for uncovered code or document exclusions.
```

---

## Appendix: Coverage by File

### Target Coverage Matrix

| File | Lines | Target | Current | Status |
|------|-------|--------|---------|--------|
| src/main.rs | 150 | 70% | - | Pending |
| src/container.rs | 800 | 85% | - | Pending |
| src/namespace.rs | 400 | 90% | - | Pending |
| src/cgroup.rs | 350 | 90% | - | Pending |
| src/image.rs | 600 | 80% | - | Pending |
| src/store.rs | 450 | 80% | - | Pending |
| src/build.rs | 500 | 80% | - | Pending |
| src/network.rs | 400 | 80% | - | Pending |

*Current values will be populated after initial test implementation.*

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-11 | Test Team | Initial version |
