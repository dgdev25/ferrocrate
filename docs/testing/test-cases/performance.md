# Performance Test Cases

**Component:** All | **Priority:** P0 | **Last Updated:** 2026-02-11

---

## Overview

Performance tests validate that FerroCrate meets all performance requirements defined in the PRD. Tests are automated and run on every commit to detect regressions.

---

## Performance Targets (from PRD)

| ID | Metric | Target | Tolerance |
|----|--------|--------|-----------|
| PERF-01 | Container startup (cold) | <100ms | ±10ms |
| PERF-02 | Container startup (warm) | <50ms | ±5ms |
| PERF-03 | Image pull throughput | >500 MB/s | ±50 MB/s |
| PERF-04 | Idle memory (no daemon) | 0 MB | 0 |
| PERF-05 | Idle memory (with daemon) | <8 MB | ±2 MB |
| PERF-06 | Per-container overhead | <2 MB | ±0.5 MB |
| PERF-07 | Build performance | Within 15% of BuildKit | ±5% |
| PERF-08 | CLI binary size | <15 MB | ±1 MB |
| PERF-09 | AI inference (WASM) | <1 ms | ±0.2 ms |

---

## Test Categories

### 1. Container Startup Performance (PERF-01, PERF-02)

#### TC-PERF-001: Cold container startup

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-001 |
| **Priority** | P0 |
| **Type** | Performance |
| **Target** | <100ms |

**Preconditions:**
- System rebooted or caches cleared
- No pre-warmed namespaces

**Steps:**
1. Clear all caches
2. Measure: `time ferrocrate run --rm alpine:latest echo test`
3. Repeat 10 times
4. Calculate p50, p95, p99

**Expected Result:**
- p50 < 80ms
- p95 < 100ms
- p99 < 120ms

---

#### TC-PERF-002: Warm container startup

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-002 |
| **Priority** | P0 |
| **Type** | Performance |
| **Target** | <50ms |

**Preconditions:**
- Namespace cache warmed
- Image in local store

**Steps:**
1. Warm cache with initial run
2. Measure 100 consecutive starts
3. Calculate percentiles

**Expected Result:**
- p50 < 40ms
- p95 < 50ms
- p99 < 60ms

---

#### TC-PERF-003: Startup with port mapping

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-003 |
| **Priority** | P0 |
| **Type** | Performance |
| **Target** | <120ms |

**Steps:**
1. Measure: `time ferrocrate run --rm -p 8080:80 nginx:alpine`
2. Include port mapping overhead

**Expected Result:**
- Additional overhead < 20ms

---

#### TC-PERF-004: Startup with volume mount

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-004 |
| **Priority** | P0 |
| **Type** | Performance |
| **Target** | <110ms |

**Steps:**
1. Measure: `time ferrocrate run --rm -v /tmp/test:/data alpine echo test`

**Expected Result:**
- Mount overhead < 10ms

---

#### TC-PERF-005: Startup with network mode

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-005 |
| **Priority** | P0 |
| **Type** | Performance |

**Steps:**
1. Measure host network startup
2. Measure bridge network startup
3. Compare overhead

**Expected Result:**
- Host network: <50ms
- Bridge network: <100ms

---

### 2. Image Pull Performance (PERF-03)

#### TC-PERF-010: Image pull throughput

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-010 |
| **Priority** | P0 |
| **Type** | Performance |
| **Target** | >500 MB/s |

**Preconditions:**
- 1 Gbps network connection
- Large image available (1GB+)

**Steps:**
1. Remove image from local store
2. Measure: `time ferrocrate pull large-image:latest`
3. Calculate MB/s from image size

**Expected Result:**
- Throughput > 500 MB/s
- Network saturation achieved

---

#### TC-PERF-011: Parallel image pulls

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-011 |
| **Priority** | P0 |
| **Type** | Performance |

**Steps:**
1. Pull 5 images simultaneously
2. Measure aggregate throughput

**Expected Result:**
- Parallel pulls scale linearly
- No significant slowdown per image

---

#### TC-PERF-012: Layer deduplication performance

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-012 |
| **Priority** | P0 |
| **Type** | Performance |

**Preconditions:**
- Base image already present

**Steps:**
1. Measure pull of derived image
2. Verify skipped layers

**Expected Result:**
- Only new layers downloaded
- Significant time savings

---

### 3. Memory Usage (PERF-04, PERF-05, PERF-06)

#### TC-PERF-020: Idle memory without daemon

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-020 |
| **Priority** | P0 |
| **Type** | Performance |
| **Target** | 0 MB |

**Preconditions:**
- No containers running
- Daemon stopped

**Steps:**
1. Verify no ferrocrate processes
2. Check memory usage

**Expected Result:**
- 0 MB RSS (no background processes)

---

#### TC-PERF-021: Idle memory with daemon

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-021 |
| **Priority** | P0 |
| **Type** | Performance |
| **Target** | <8 MB |

**Preconditions:**
- ferro-mgr daemon running
- No containers

**Steps:**
1. Start daemon
2. Measure RSS: `ps -o rss= -p $(pidof ferro-mgr)`

**Expected Result:**
- RSS < 8 MB

---

#### TC-PERF-022: Per-container overhead

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-022 |
| **Priority** | P0 |
| **Type** | Performance |
| **Target** | <2 MB |

**Preconditions:**
- Daemon running
- Baseline memory recorded

**Steps:**
1. Start 10 containers
2. Measure memory delta
3. Calculate per-container overhead

**Expected Result:**
- (Total - Baseline) / 10 < 2 MB

---

#### TC-PERF-023: Memory growth over time

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-023 |
| **Priority** | P0 |
| **Type** | Performance |

**Steps:**
1. Run container for 1 hour
2. Monitor memory usage
3. Start/stop 100 containers
4. Check for memory leaks

**Expected Result:**
- No memory growth
- Memory released after container removal

---

#### TC-PERF-024: Large container count memory

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-024 |
| **Priority** | P0 |
| **Type** | Performance |

**Steps:**
1. Start 100 containers
2. Measure total memory
3. Verify linear scaling

**Expected Result:**
- Memory scales linearly
- No exponential growth

---

### 4. Build Performance (PERF-07)

#### TC-PERF-030: Simple build

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-030 |
| **Priority** | P0 |
| **Type** | Performance |
| **Target** | Within 15% of BuildKit |

```dockerfile
FROM alpine:latest
RUN apk add --no-cache curl
COPY test.txt /app/
```

**Steps:**
1. Build with ferrocrate
2. Build with Docker BuildKit
3. Compare times

**Expected Result:**
- ferrocrate within 15% of BuildKit

---

#### TC-PERF-031: Multi-stage build

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-031 |
| **Priority** | P0 |
| **Type** | Performance |
| **Target** | Within 15% of BuildKit |

**Steps:**
1. Build complex multi-stage Dockerfile
2. Compare with BuildKit

**Expected Result:**
- ferrocrate within 15%

---

#### TC-PERF-032: Cached build

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-032 |
| **Priority** | P0 |
| **Type** | Performance |

**Preconditions:**
- Previous build cached

**Steps:**
1. Rebuild unchanged Dockerfile
2. Verify cache hits

**Expected Result:**
- Significantly faster than uncached
- Only metadata operations

---

### 5. Binary Size (PERF-08)

#### TC-PERF-040: Release binary size

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-040 |
| **Priority** | P0 |
| **Type** | Performance |
| **Target** | <15 MB |

**Steps:**
1. Build release binary: `cargo build --release`
2. Strip symbols: `strip target/release/ferrocrate`
3. Measure size: `ls -l target/release/ferrocrate`

**Expected Result:**
- Binary size < 15 MB

---

#### TC-PERF-041: Binary size by feature

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-041 |
| **Priority** | P0 |
| **Type** | Performance |

**Steps:**
1. Build minimal features
2. Build standard features
3. Build full features
4. Compare sizes

**Expected Result:**
| Tier | Target Size |
|------|-------------|
| Minimal | <8 MB |
| Standard | <12 MB |
| Full | <15 MB |

---

### 6. AI Inference Performance (PERF-09)

#### TC-PERF-050: WASM inference latency

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-050 |
| **Priority** | P0 |
| **Type** | Performance |
| **Target** | <1 ms |

**Preconditions:**
- WASM module loaded
- Model initialized

**Steps:**
1. Measure 1000 inference calls
2. Calculate latency distribution

```rust
let start = std::time::Instant::now();
let result = ferro_mind::predict(&input);
let elapsed = start.elapsed();
```

**Expected Result:**
- p50 < 0.8 ms
- p95 < 1.0 ms
- p99 < 1.5 ms

---

#### TC-PERF-051: Resource prediction overhead

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-051 |
| **Priority** | P0 |
| **Type** | Performance |

**Steps:**
1. Start container with prediction enabled
2. Measure prediction time
3. Verify no startup delay

**Expected Result:**
- Prediction adds <5ms to startup

---

### 7. Network Performance

#### TC-PERF-060: Bridge network throughput

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-060 |
| **Priority** | P0 |
| **Type** | Performance |

**Preconditions:**
- Two containers on bridge network

**Steps:**
1. Run iperf3 server in container A
2. Run iperf3 client in container B
3. Measure throughput

**Expected Result:**
- Within 10% of native performance
- >9 Gbps on 10 Gbps link

---

#### TC-PERF-061: Port mapping overhead

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-061 |
| **Priority** | P0 |
| **Type** | Performance |

**Steps:**
1. Run iperf3 with port mapping
2. Compare to direct connection
3. Measure overhead

**Expected Result:**
- <5% overhead from port mapping

---

#### TC-PERF-062: eBPF vs iptables

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-062 |
| **Priority** | P1 |
| **Type** | Performance |

**Steps:**
1. Measure throughput with eBPF
2. Measure throughput with iptables
3. Compare

**Expected Result:**
- eBPF >= iptables performance
- Preferably faster

---

### 8. Storage Performance

#### TC-PERF-070: OverlayFS write performance

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-070 |
| **Priority** | P0 |
| **Type** | Performance |

**Steps:**
1. Run fio write test in container
2. Measure IOPS and throughput

**Expected Result:**
- Within 5% of native filesystem

---

#### TC-PERF-071: Volume mount performance

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-071 |
| **Priority** | P0 |
| **Type** | Performance |

**Steps:**
1. Mount host volume
2. Run fio test
3. Compare to native

**Expected Result:**
- Native performance (bind mount)

---

#### TC-PERF-072: Image layer extraction

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-072 |
| **Priority** | P0 |
| **Type** | Performance |

**Preconditions:**
- Large layer (500MB+)

**Steps:**
1. Measure layer extraction time
2. Calculate MB/s

**Expected Result:**
- >200 MB/s extraction speed

---

### 9. Concurrency Performance

#### TC-PERF-080: Parallel container creation

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-080 |
| **Priority** | P0 |
| **Type** | Performance |

**Steps:**
1. Create 50 containers simultaneously
2. Measure total time
3. Calculate per-container time

**Expected Result:**
- Scales with CPU cores
- No lock contention

---

#### TC-PERF-081: Concurrent API requests

| Attribute | Value |
|-----------|-------|
| **ID** | TC-PERF-081 |
| **Priority** | P0 |
| **Type** | Performance |

**Steps:**
1. Send 100 concurrent API requests
2. Measure response times
3. Verify no degradation

**Expected Result:**
- Consistent response times
- No request failures

---

### 10. Benchmark Suite

```rust
// benches/runtime_bench.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_container_lifecycle(c: &mut Criterion) {
    let runtime = FerroRuntime::new();
    let config = ContainerConfig {
        image: "alpine:latest",
        command: vec!["echo".into(), "test".into()],
        ..Default::default()
    };

    // Cold start benchmark
    c.bench_function("container_cold_start", |b| {
        b.iter(|| {
            let container = runtime.create(black_box(&config)).unwrap();
            container.start().unwrap();
            container.wait().unwrap();
            container.remove().unwrap();
        })
    });

    // Warm start benchmark (pre-warmed namespace)
    let mut group = c.benchmark_group("container_warm_start");
    runtime.warm_namespace_cache();
    group.bench_function("cached_namespace", |b| {
        b.iter(|| {
            let container = runtime.create(black_box(&config)).unwrap();
            container.start().unwrap();
            container.wait().unwrap();
            container.remove().unwrap();
        })
    });
    group.finish();
}

fn bench_image_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("image_pull");
    for size in [10, 50, 100, 500].iter() {
        group.bench_with_input(BenchmarkId::new("mb", size), size, |b, &size| {
            let image = format!("test-image:{}mb", size);
            b.iter(|| {
                runtime.pull_image(black_box(&image)).unwrap();
                runtime.remove_image(&image).unwrap();
            })
        });
    }
    group.finish();
}

fn bench_ai_inference(c: &mut Criterion) {
    let model = ferro_mind::load_wasm_model().unwrap();

    c.bench_function("wasm_inference", |b| {
        let input = vec![0.5; 128];
        b.iter(|| model.predict(black_box(&input)))
    });
}

criterion_group!(benches, bench_container_lifecycle, bench_image_operations, bench_ai_inference);
criterion_main!(benches);
```

---

## Regression Detection

### Baseline Management

```yaml
# .github/workflows/performance.yml
name: Performance Regression

on:
  pull_request:
    branches: [main]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run benchmarks
        run: cargo bench -- --save-baseline pr-${{ github.event.number }}

      - name: Compare with main
        run: cargo bench -- --baseline main

      - name: Fail on regression
        run: |
          # Fail if any benchmark is >10% slower
          if grep -q "regressed" criterion_output.txt; then
            echo "Performance regression detected!"
            exit 1
          fi
```

---

## Test Execution Matrix

| Test ID | Priority | CI | Nightly | Release |
|---------|----------|-----|---------|---------|
| TC-PERF-001 | P0 | X | X | X |
| TC-PERF-002 | P0 | X | X | X |
| TC-PERF-010 | P0 | X | X | X |
| TC-PERF-020 | P0 | X | X | X |
| TC-PERF-021 | P0 | X | X | X |
| TC-PERF-022 | P0 | X | X | X |
| TC-PERF-030 | P0 | - | X | X |
| TC-PERF-040 | P0 | X | X | X |
| TC-PERF-050 | P0 | X | X | X |
| TC-PERF-060 | P0 | - | X | X |
| TC-PERF-070 | P0 | - | X | X |
| TC-PERF-080 | P0 | - | X | X |
