# Benchmark Definitions

**Version:** 1.0 | **Date:** February 11, 2026 | **Status:** Active

---

## Overview

This document defines the performance benchmarks for FerroCrate, including methodology, targets, measurement techniques, and acceptance criteria. All benchmarks are derived from PRD requirements PERF-01 through PERF-09.

---

## Benchmark Categories

| Category | ID | Description |
|----------|-----|-------------|
| Startup | BENCH-START | Container creation and execution latency |
| Throughput | BENCH-THRU | Data transfer and processing rates |
| Memory | BENCH-MEM | Memory consumption and efficiency |
| Build | BENCH-BUILD | Image build performance |
| AI | BENCH-AI | Inference and prediction latency |
| Network | BENCH-NET | Network I/O performance |
| Storage | BENCH-STORE | Filesystem and volume performance |
| Concurrency | BENCH-CONC | Parallel operation scaling |

---

## 1. Container Startup Benchmarks (PERF-01, PERF-02)

### BENCH-START-01: Cold Container Startup

**Target:** <100ms (p95)

**Definition:** Time from API call to process execution with no cached state.

**Methodology:**
```rust
fn bench_cold_startup(c: &mut Criterion) {
    c.bench_function("cold_startup_alpine", |b| {
        // Clear caches before each iteration
        system::clear_caches();

        b.iter(|| {
            let start = std::time::Instant::now();

            // Full cold start
            let container = runtime.create(ContainerConfig {
                image: "alpine:latest",
                command: vec!["echo", "test"],
                ..Default::default()
            })?;
            container.start()?;
            container.wait()?;

            black_box(start.elapsed())
        })
    });
}
```

**Measurement Points:**
1. API call received
2. Container record created
3. Namespace configured
4. Rootfs mounted
5. Process forked
6. Process executing

**Baseline Comparisons:**
| Runtime | p50 | p95 | p99 |
|---------|-----|-----|-----|
| runc | 45ms | 70ms | 90ms |
| crun | 30ms | 50ms | 70ms |
| **FerroCrate Target** | 60ms | 100ms | 120ms |

---

### BENCH-START-02: Warm Container Startup

**Target:** <50ms (p95)

**Definition:** Time from API call to process execution with pre-warmed namespace cache.

**Methodology:**
```rust
fn bench_warm_startup(c: &mut Criterion) {
    // Pre-warm namespace cache
    runtime.warm_namespace_cache();

    c.bench_function("warm_startup_alpine", |b| {
        b.iter(|| {
            let start = std::time::Instant::now();

            let container = runtime.create(cached_config())?;
            container.start()?;
            container.wait()?;

            black_box(start.elapsed())
        })
    });
}
```

**Cache Conditions:**
- User namespace pre-created
- Network namespace pre-configured
- Image layers in page cache

---

### BENCH-START-03: Container Startup with Port Mapping

**Target:** <120ms (p95)

**Variables:**
- Ports mapped: 1, 5, 10, 50
- Protocol: TCP, UDP

**Methodology:**
```rust
fn bench_startup_ports(c: &mut Criterion) {
    let mut group = c.benchmark_group("startup_ports");

    for port_count in [1, 5, 10, 50] {
        let config = config_with_ports(port_count);

        group.bench_with_input(
            BenchmarkId::new("ports", port_count),
            &config,
            |b, config| {
                b.iter(|| {
                    let container = runtime.create(config)?;
                    container.start()?;
                    container.wait()
                })
            }
        );
    }
    group.finish();
}
```

---

### BENCH-START-04: Container Startup with Volume Mounts

**Target:** <110ms (p95)

**Variables:**
- Mounts: 1, 5, 10, 20
- Mount type: bind, volume, tmpfs

---

## 2. Image Pull Benchmarks (PERF-03)

### BENCH-THRU-01: Image Pull Throughput

**Target:** >500 MB/s

**Definition:** Sustained download rate for image layers.

**Methodology:**
```rust
fn bench_image_pull(c: &mut Criterion) {
    let mut group = c.benchmark_group("image_pull");
    group.throughput(Throughput::Bytes(image_size));

    group.bench_function("pull_nginx", |b| {
        b.iter(|| {
            let start = std::time::Instant::now();
            runtime.pull_image("nginx:latest")?;
            let elapsed = start.elapsed();

            // Calculate throughput
            let throughput = image_size as f64 / elapsed.as_secs_f64();
            black_box(throughput)
        })
    });
}
```

**Test Images:**
| Image | Size | Layers | Purpose |
|-------|------|--------|---------|
| alpine:latest | 5 MB | 1 | Baseline |
| nginx:alpine | 25 MB | 5 | Small |
| node:18-alpine | 170 MB | 10 | Medium |
| tensorflow:latest | 1.5 GB | 20 | Large |
| pytorch:latest | 3 GB | 25 | X-Large |

**Network Conditions:**
- 1 Gbps link (theoretical max: 125 MB/s)
- 10 Gbps link (theoretical max: 1.25 GB/s)

---

### BENCH-THRU-02: Parallel Image Pull

**Target:** Linear scaling up to network capacity

**Variables:**
- Parallel pulls: 1, 2, 5, 10

**Acceptance Criteria:**
- Aggregate throughput scales linearly
- Individual pull time increases < 20%

---

## 3. Memory Benchmarks (PERF-04, PERF-05, PERF-06)

### BENCH-MEM-01: Idle Memory (No Daemon)

**Target:** 0 MB

**Definition:** Memory consumption with no containers and no daemon running.

**Verification:**
```bash
# Verify no ferrocrate processes
pgrep -f ferrocrate && exit 1

# Check system memory
cat /proc/meminfo | grep MemFree
```

---

### BENCH-MEM-02: Idle Memory (With Daemon)

**Target:** <8 MB RSS

**Methodology:**
```rust
fn bench_daemon_memory() {
    let daemon = start_daemon();

    // Wait for initialization
    sleep(Duration::from_secs(5));

    // Measure RSS
    let rss = get_process_rss(daemon.pid())?;

    assert!(rss < 8 * 1024 * 1024, "RSS {} exceeds 8MB", rss);
}
```

---

### BENCH-MEM-03: Per-Container Overhead

**Target:** <2 MB per container

**Methodology:**
```rust
fn bench_container_overhead() {
    let baseline = get_daemon_rss()?;

    // Start containers incrementally
    for i in 1..=100 {
        runtime.create(&config)?.start()?;

        let current = get_daemon_rss()?;
        let overhead = (current - baseline) / i;

        assert!(overhead < 2 * 1024 * 1024);
    }
}
```

---

### BENCH-MEM-04: Memory Efficiency Over Time

**Target:** No memory leaks

**Methodology:**
1. Start container
2. Run for 1 hour with periodic operations
3. Verify memory stable
4. Stop container
5. Verify memory released

---

## 4. Build Benchmarks (PERF-07)

### BENCH-BUILD-01: Simple Build

**Target:** Within 15% of Docker BuildKit

**Dockerfile:**
```dockerfile
FROM alpine:latest
RUN apk add --no-cache curl
COPY file.txt /app/
```

**Methodology:**
```rust
fn bench_simple_build(c: &mut Criterion) {
    c.bench_function("build_simple", |b| {
        b.iter(|| {
            ferro_build::build(BuildConfig {
                context: "fixtures/simple-build",
                dockerfile: "Dockerfile",
                ..Default::default()
            })
        })
    });
}
```

**Comparison Script:**
```bash
# FerroCrate
time ferrocrate build -t test .

# Docker BuildKit
time docker build -t test .

# Compare
# FerroCrate must be within 15% of Docker time
```

---

### BENCH-BUILD-02: Multi-Stage Build

**Dockerfile:**
```dockerfile
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp

FROM alpine:latest
COPY --from=builder /app/myapp /usr/local/bin/
CMD ["myapp"]
```

---

### BENCH-BUILD-03: Cached Build

**Target:** <10% of uncached time

**Methodology:**
1. Build once to populate cache
2. Rebuild identical Dockerfile
3. Verify cache hits

---

## 5. AI Inference Benchmarks (PERF-09)

### BENCH-AI-01: WASM Neural Inference

**Target:** <1 ms per prediction

**Methodology:**
```rust
fn bench_wasm_inference(c: &mut Criterion) {
    let model = ferro_mind::load_model("resource_predictor.wasm")?;
    let input = vec![0.5f32; 128];

    c.bench_function("wasm_predict", |b| {
        b.iter(|| {
            let start = std::time::Instant::now();
            let result = model.predict(black_box(&input))?;
            black_box(start.elapsed())
        })
    });
}
```

**Acceptance Criteria:**
| Percentile | Target |
|------------|--------|
| p50 | < 0.8 ms |
| p95 | < 1.0 ms |
| p99 | < 1.5 ms |

---

### BENCH-AI-02: Resource Prediction Latency

**Target:** <5 ms additional startup time

**Methodology:**
1. Measure startup without AI
2. Measure startup with AI prediction
3. Compare delta

---

### BENCH-AI-03: Anomaly Detection

**Target:** <10 ms per analysis

**Methodology:**
```rust
fn bench_anomaly_detection(c: &mut Criterion) {
    let detector = ferro_mind::AnomalyDetector::new();
    let metrics = generate_container_metrics();

    c.bench_function("anomaly_detect", |b| {
        b.iter(|| {
            detector.analyze(black_box(&metrics))
        })
    });
}
```

---

## 6. Network Benchmarks

### BENCH-NET-01: Bridge Network Throughput

**Target:** Within 10% of native

**Methodology:**
```bash
# Server container
ferrocrate run --name server alpine iperf3 -s

# Client container
ferrocrate run alpine iperf3 -c server
```

**Acceptance:**
- Throughput > 9 Gbps on 10 Gbps link
- Latency < 0.1 ms

---

### BENCH-NET-02: Port Mapping Overhead

**Target:** <5% overhead

**Methodology:**
1. Measure throughput without port mapping
2. Measure with port mapping
3. Calculate overhead percentage

---

### BENCH-NET-03: Container-to-Container Latency

**Target:** <0.05 ms (localhost equivalent)

**Methodology:**
```bash
# Ping between containers
ferrocrate run --name c1 alpine ping -c 100 c2
```

---

## 7. Storage Benchmarks

### BENCH-STORE-01: OverlayFS Write Performance

**Target:** Within 5% of native

**Methodology:**
```bash
# fio test inside container
ferrocrate run -v /tmp/fio-test:/data alpine fio --name=test \
    --ioengine=libaio --direct=1 --bs=4k --numjobs=4 \
    --size=1G --rw=randwrite
```

---

### BENCH-STORE-02: Layer Extraction Speed

**Target:** >200 MB/s

**Methodology:**
```rust
fn bench_layer_extraction(c: &mut Criterion) {
    let large_layer = load_layer("500mb-layer.tar.gz");

    c.bench_function("extract_layer", |b| {
        b.iter(|| {
            ferro_store::extract_layer(black_box(&large_layer))
        })
    });
}
```

---

### BENCH-STORE-03: Volume Mount Performance

**Target:** Native performance (bind mount)

**Methodology:**
1. Create bind mount to host directory
2. Run fio benchmark
3. Compare to native

---

## 8. Concurrency Benchmarks

### BENCH-CONC-01: Parallel Container Creation

**Target:** Linear scaling with CPU cores

**Methodology:**
```rust
fn bench_parallel_create(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_create");

    for count in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::new("containers", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    (0..count)
                        .map(|_| {
                            runtime.spawn(|| {
                                runtime.create(&config)?.start()?.wait()
                            })
                        })
                        .collect::<Vec<_>>()
                        .into_iter()
                        .map(|h| h.join().unwrap())
                        .collect::<Result<Vec<_>>>()
                })
            }
        );
    }
}
```

---

### BENCH-CONC-02: Concurrent API Requests

**Target:** Consistent latency under load

**Variables:**
- Concurrent requests: 10, 50, 100, 500
- Request type: create, inspect, list, logs

---

## 9. Benchmark Infrastructure

### Directory Structure

```
benches/
├── runtime_bench.rs      # Container lifecycle benchmarks
├── image_bench.rs        # Image operation benchmarks
├── network_bench.rs      # Network benchmarks
├── storage_bench.rs      # Storage benchmarks
├── ai_bench.rs           # AI/ML benchmarks
├── fixtures/
│   ├── dockerfiles/      # Test Dockerfiles
│   ├── images/           # Test image artifacts
│   └── configs/          # Test configurations
└── scripts/
    ├── compare-docker.sh # Docker comparison script
    └── regression-check.sh
```

### Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench runtime_bench

# Run with specific filter
cargo bench "startup"

# Save baseline
cargo bench -- --save-baseline main

# Compare with baseline
cargo bench -- --baseline main
```

---

## 10. Regression Detection

### Thresholds

| Metric | Warning | Failure |
|--------|---------|---------|
| Latency (p95) | +5% | +10% |
| Throughput | -5% | -10% |
| Memory | +5% | +10% |

### CI Integration

```yaml
# .github/workflows/benchmark.yml
name: Benchmarks

on:
  pull_request:
    branches: [main]

jobs:
  benchmark:
    runs-on: [self-hosted, benchmark]
    steps:
      - uses: actions/checkout@v4

      - name: Run benchmarks
        run: cargo bench -- --save-baseline pr-${{ github.event.number }}

      - name: Compare with main
        run: |
          cargo bench -- --baseline main 2>&1 | tee results.txt

      - name: Check for regressions
        run: |
          python scripts/check_regression.py results.txt
```

---

## 11. Reporting

### Dashboard Metrics

| Category | Metric | Target | Current |
|----------|--------|--------|---------|
| Startup | Cold p95 | 100ms | TBD |
| Startup | Warm p95 | 50ms | TBD |
| Throughput | Pull | 500 MB/s | TBD |
| Memory | Daemon | 8 MB | TBD |
| Memory | Per-container | 2 MB | TBD |
| AI | Inference | 1 ms | TBD |

### Report Format

```markdown
# Benchmark Report - YYYY-MM-DD

## Summary
- Total benchmarks: 45
- Regressions: 0
- Improvements: 3

## Details

### Container Startup
| Benchmark | Baseline | Current | Change |
|-----------|----------|---------|--------|
| cold_startup | 95ms | 92ms | -3% |
| warm_startup | 45ms | 44ms | -2% |

### Image Operations
| Benchmark | Baseline | Current | Change |
|-----------|----------|---------|--------|
| pull_throughput | 520 MB/s | 535 MB/s | +3% |
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-11 | Test Team | Initial version |
