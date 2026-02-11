# EPIC-02: Performance

**Phase:** Phase 1, Phase 2 (Weeks 1-14) | **Tasks:** 5 | **Story Points:** 35

---

## 1. Overview

This epic focuses on achieving the performance targets that differentiate FerroCrate from Docker and other container runtimes. Key targets include sub-100ms startup, zero idle memory, and fast image operations.

### User Stories Covered
- US-2.1: Binary tiers: ~5 MB (minimal), ~12 MB (standard), ~18 MB (full), ~45 MB (full+agents)
- US-2.2: Container startup under 100ms
- US-2.3: File-level image deduplication
- US-2.4: Lazy image pulling for large containers

### PRD Requirements Covered
- PERF-01 through PERF-08 (Performance)
- IMG-03, IMG-04, IMG-05 (Image Management)

---

## 2. Performance Targets

| Metric | Target | Docker Baseline | Improvement |
|--------|--------|-----------------|-------------|
| Container startup (cold) | <100ms | ~500ms | 5x |
| Container startup (warm) | <50ms | ~200ms | 4x |
| Image pull throughput | >500 MB/s | ~300 MB/s | 1.7x |
| Idle memory (no daemon) | 0 MB | 120-180 MB | Infinite |
| Idle memory (daemon) | <8 MB | 120-180 MB | 15-22x |
| Per-container overhead | <2 MB | ~10 MB | 5x |
| Binary size (minimal) | ~5 MB | ~70 MB | 14x |
| Binary size (standard) | ~12 MB | ~70 MB | 5.8x |
| Binary size (full) | ~18 MB | ~70 MB | 3.9x |
| Binary size (full+agents) | ~45 MB | ~70 MB | 1.6x |
| AI inference | <1 ms | N/A | N/A |

---

## 3. Optimization Strategies

### 3.1 Blake3 Content Hashing

Replace SHA-256 with Blake3 for internal operations, achieving 10x faster hashing.

```rust
// Parallel Blake3 computation
pub fn hash_layer(data: &[u8]) -> Blake3Hash {
    blake3::Hasher::new()
        .update_with_join::<join::RayonJoin>(data)
        .finalize()
        .into()
}

// Benchmark results (1GB data):
// SHA-256:  ~1.7 seconds
// Blake3:   ~0.17 seconds
```

### 3.2 Zstd Compression

Use Zstd level 3 for faster decompression than gzip.

```
| Algorithm | Compress | Decompress | Ratio |
|-----------|----------|------------|-------|
| gzip -9   | 45s      | 12s        | 2.7x  |
| zstd -3   | 8s       | 3s         | 2.7x  |
| zstd -19  | 120s     | 3s         | 2.9x  |
```

### 3.3 Parallel Image Pull

Pull layers in parallel with connection pooling.

```rust
pub async fn pull_image_parallel(
    client: &OciClient,
    manifest: &Manifest,
    concurrency: usize,
) -> Result<Image> {
    let layers = manifest.layers();

    let stream = futures::stream::iter(layers)
        .map(|layer| client.pull_blob(&layer.digest))
        .buffer_unordered(concurrency);

    let results: Vec<_> = stream.try_collect().await?;
    // ...
}
```

### 3.4 Lazy Image Pulling

Start container before full image download.

```rust
pub struct LazyPullConfig {
    /// Pull only manifest initially
    pub manifest_only: bool,
    /// Pull layers on-demand when accessed
    pub on_demand: bool,
    /// Background pull rate limit
    pub background_rate: Option<u64>,
}

impl LazyPullConfig {
    pub fn for_container_start() -> Self {
        Self {
            manifest_only: true,
            on_demand: true,
            background_rate: Some(50_000_000), // 50 MB/s
        }
    }
}
```

### 3.5 File-Level Deduplication

Deduplicate at file level, not just layer level.

```rust
pub struct ContentStore {
    /// Blake3 hash -> file path
    file_index: HashMap<[u8; 32], PathBuf>,
    /// Storage savings tracker
    savings: StorageSavings,
}

impl ContentStore {
    pub fn store_file(&mut self, data: &[u8]) -> Result<FileRef> {
        let hash = blake3::hash(data);

        // Check if file already exists
        if let Some(path) = self.file_index.get(hash.as_bytes()) {
            self.savings.deduplicated_bytes += data.len() as u64;
            return Ok(FileRef::deduplicated(path));
        }

        // Store new file
        let path = self.write_blob(&hash, data)?;
        self.file_index.insert(*hash.as_bytes(), path.clone());

        Ok(FileRef::new(path))
    }
}
```

---

## 4. Tasks

| ID | Title | Points | Milestone | Status |
|----|-------|--------|-----------|--------|
| TASK-007 | Implement ferro-store crate skeleton | 5 | M1 | Not Started |
| TASK-008 | Implement Blake3 content-addressable storage | 6 | M1 | Not Started |
| TASK-009 | Implement OCI registry client | 8 | M1 | Not Started |
| TASK-010 | Implement OverlayFS storage driver | 6 | M1 | Not Started |
| TASK-011 | Implement image build from Dockerfile | 10 | M1 | Not Started |

**Total Story Points:** 35

---

## 5. Benchmarks

### Container Startup

```rust
#[bench]
fn bench_container_startup_cold(b: &mut Bencher) {
    let runtime = Runtime::new().unwrap();

    b.iter(|| {
        let container = runtime.create_container(spec.clone()).unwrap();
        let start = Instant::now();
        container.start().unwrap();
        let elapsed = start.elapsed();

        container.delete().unwrap();
        elapsed
    });

    // Target: <100ms
}

#[bench]
fn bench_container_startup_warm(b: &mut Bencher) {
    // Pre-pull image, then measure start time
    // Target: <50ms
}
```

### Image Operations

```rust
#[bench]
fn bench_image_pull(b: &mut Bencher) {
    // Pull Ubuntu 22.04 image
    // Target: >500 MB/s on 1Gbps link
}

#[bench]
fn bench_hash_layer(b: &mut Bencher) {
    let data = generate_test_data(1_000_000_000); // 1GB

    b.iter(|| {
        blake3::hash(&data)
    });

    // Target: >5 GB/s
}
```

### Memory Usage

```rust
#[test]
fn test_idle_memory() {
    // Start fresh
    let baseline = get_process_memory();

    // Create runtime (no daemon)
    let runtime = Runtime::new().unwrap();

    // Verify zero additional memory
    let current = get_process_memory();
    assert_eq!(current, baseline, "Idle memory should be zero");

    // Create container
    let container = runtime.create_container(spec).unwrap();

    // Verify <2MB overhead
    let overhead = get_process_memory() - baseline;
    assert!(overhead < 2_000_000, "Per-container overhead should be <2MB");
}
```

---

## 6. Profiling Strategy

### Continuous Profiling

```bash
# CPU profiling
cargo flamegraph --root -- ferrocrate run alpine

# Memory profiling
valgrind --tool=massif ferrocrate run alpine

# I/O profiling
iotop -p $(pidof ferrocrate)
```

### Performance CI

```yaml
# .github/workflows/performance.yml
name: Performance
on: [push]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo bench --output-format json > bench.json
      - uses: benchmark-action/github-action-benchmark@v1
        with:
          tool: 'cargo'
          output-file-path: bench.json
          fail-on-alert: true
```

---

## 7. Optimization Opportunities

### Short-Term (v1.0)
1. Blake3 for content hashing
2. Zstd level 3 compression
3. Parallel layer pull
4. File-level deduplication

### Medium-Term (v1.1)
1. Lazy image pulling
2. Build cache optimization
3. Memory-mapped layer access

### Long-Term (v2.0)
1. ruvector similarity matching
2. Predictive layer prefetching
3. GPU-accelerated compression

---

## 8. Acceptance Criteria

This epic is complete when:

1. **Startup Performance**
   - [ ] Container startup <100ms cold
   - [ ] Container startup <50ms warm
   - [ ] Consistent performance across runs

2. **Memory Efficiency**
   - [ ] 0 MB idle without daemon
   - [ ] <8 MB with daemon
   - [ ] <2 MB per-container overhead

3. **Throughput**
   - [ ] Image pull >500 MB/s
   - [ ] Hashing >5 GB/s
   - [ ] Build within 15% of BuildKit

4. **Binary Size**
   - [ ] Minimal static binary ~5 MB
   - [ ] Standard binary ~12 MB
   - [ ] Full binary ~18 MB
   - [ ] Full + agents binary ~45 MB
   - [ ] Stripped symbols
   - [ ] musl libc for portability

---

*Epic Owner: TBD | Last Updated: 2026-02-11*
