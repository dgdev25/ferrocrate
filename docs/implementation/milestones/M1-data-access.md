# M1: Data Access Milestone

**⚠️ LEGACY NOTICE:** This milestone structure has been superseded by the 6-phase implementation plan (Phase 1-6). Maintained for historical reference only. See `INDEX.md` for the current Phase 1-6 timeline.

**Duration:** Weeks 5-8 | **Story Points:** 35 | **Tasks:** 5

---

## 1. Objective

Deliver complete image management capabilities including OCI registry integration, content-addressable storage with Blake3 deduplication, Zstd compression, and OverlayFS layer stacking. Enable pulling images from registries and building images from Dockerfiles.

## 2. Scope

### In Scope
- ferro-store crate implementation
- OCI Distribution Spec v1.1 client
- Content-addressable storage with Blake3
- Zstd/gzip layer compression
- OverlayFS storage driver
- Image build from Dockerfile (95%+ directive support)
- Layer caching with file-level granularity
- Multi-stage builds

### Out of Scope
- Networking (M2)
- AI features (M3)
- Compose orchestration (M3)
- ferrofile.toml format (post-v1.0)

## 3. Architecture

### Component Structure

```
ferro-store/
+-- Cargo.toml
+-- src/
|   +-- lib.rs              # Crate entry point
|   +-- store/
|   |   +-- mod.rs          # Store abstraction
|   |   +-- content.rs      # Content-addressable storage
|   |   +-- blob.rs         # Blob management
|   |   +-- reference.rs    # Image references
|   +-- registry/
|   |   +-- mod.rs          # Registry client
|   |   +-- oci.rs          # OCI Distribution client
|   |   +-- auth.rs         # Authentication
|   |   +-- manifest.rs     # Manifest handling
|   |   +-- blob_upload.rs  # Blob upload
|   +-- layer/
|   |   +-- mod.rs          # Layer abstraction
|   |   +-- tar.rs          # Tar unpacking
|   |   +-- whiteout.rs     # OCI whiteout handling
|   |   +-- compression.rs  # Zstd/gzip
|   +-- hash/
|   |   +-- mod.rs          # Hash utilities
|   |   +-- blake3.rs       # Blake3 hashing
|   |   +-- sha256.rs       # SHA-256 (OCI)
|   +-- overlay/
|   |   +-- mod.rs          # OverlayFS driver
|   |   +-- mount.rs        # Mount operations
|   |   +-- cleanup.rs      # Layer cleanup
|   +-- build/
|   |   +-- mod.rs          # Build system
|   |   +-- dockerfile.rs   # Dockerfile parser
|   |   +-- executor.rs     # Step executor
|   |   +-- cache.rs        # Build cache
|   |   +-- context.rs      # Build context
|   +-- error.rs            # Error types
```

### Key Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| oci-client | 0.9 | OCI registry client |
| blake3 | 1.5 | Fast content hashing |
| zstd | 0.13 | Zstd compression |
| flate2 | 1.0 | Gzip compression |
| tar | 0.4 | Tar archive handling |
| tokio | 1.35 | Async runtime |
| reqwest | 0.11 | HTTP client |
| sha2 | 0.10 | SHA-256 (OCI compliance) |

## 4. Tasks

### TASK-007: Implement ferro-store crate skeleton

**Effort:** 3 days | **Points:** 5 | **Priority:** P0 | **Depends On:** TASK-001

**Description:**
Create the image and storage management crate with content-addressable store interface, layer management, and blob storage.

**Acceptance Criteria:**
- [ ] Cargo.toml with oci-client, blake3, zstd deps
- [ ] Module structure: src/{lib.rs, store.rs, layer.rs, blob.rs}
- [ ] Trait definitions for Store, Layer, Blob
- [ ] cargo test passes

**Implementation Notes:**
```rust
// src/lib.rs
pub mod store;
pub mod registry;
pub mod layer;
pub mod hash;
pub mod overlay;
pub mod build;
pub mod error;

pub use store::Store;
pub use layer::Layer;
pub use error::Error;
```

---

### TASK-008: Implement Blake3 content-addressable storage

**Effort:** 4 days | **Points:** 6 | **Priority:** P0 | **Depends On:** TASK-007

**Description:**
Implement content-addressable blob storage using Blake3 for fast deduplication. Store files keyed by hash with SHA-256 mapping for OCI compatibility.

**Acceptance Criteria:**
- [ ] Blake3 hash computation >5GB/s
- [ ] File-level deduplication across layers
- [ ] SHA-256 computed for OCI digest
- [ ] 40%+ storage reduction vs Docker

**Implementation Notes:**
```rust
// store/content.rs
pub struct ContentStore {
    root: PathBuf,
    blake3_index: HashMap<[u8; 32], BlobRef>,
    sha256_index: HashMap<[u8; 32], [u8; 32]>, // SHA-256 -> Blake3
}

pub struct BlobRef {
    blake3: [u8; 32],
    sha256: [u8; 32],
    size: u64,
    compressed_size: u64,
    compression: Compression,
}

impl ContentStore {
    pub fn store(&mut self, data: &[u8]) -> Result<BlobRef> {
        // Parallel Blake3 computation
        let blake3 = blake3::hash(data);

        // SHA-256 for OCI
        let sha256 = sha2::Sha256::digest(data);

        // Store with deduplication
        if !self.blake3_index.contains_key(blake3.as_bytes()) {
            self.write_blob(&blake3, data)?;
        }

        Ok(BlobRef { ... })
    }

    pub fn retrieve(&self, blake3: &[u8; 32]) -> Result<Vec<u8>> { ... }
}
```

**Storage Layout:**
```
/var/lib/ferrocrate/store/
+-- blobs/
|   +-- sha256/
|   |   +-- ab/
|   |   |   +-- c123...  # Blob content
+-- index/
|   +-- blake3.db        # SQLite index
|   +-- sha256.db        # SHA-256 mapping
```

---

### TASK-009: Implement OCI registry client

**Effort:** 5 days | **Points:** 8 | **Priority:** P0 | **Depends On:** TASK-007, TASK-008

**Description:**
Implement OCI Distribution Spec v1.1 client for pull/push operations. Support Docker Hub, GHCR, ECR, GCR with authentication.

**Acceptance Criteria:**
- [ ] Pull from Docker Hub succeeds
- [ ] Pull from GHCR with auth succeeds
- [ ] Push to local registry succeeds
- [ ] >500 MB/s pull throughput on 1Gbps

**Implementation Notes:**
```rust
// registry/oci.rs
pub struct OciClient {
    http: reqwest::Client,
    auth: AuthConfig,
}

impl OciClient {
    pub async fn pull_manifest(&self, ref: &ImageReference) -> Result<Manifest> { ... }
    pub async fn pull_blob(&self, digest: &str) -> Result<impl Stream<Item=Bytes>> { ... }
    pub async fn push_blob(&self, data: Vec<u8>) -> Result<String> { ... }
    pub async fn push_manifest(&self, manifest: &Manifest, tag: &str) -> Result<()> { ... }
}

// Parallel blob download
pub async fn pull_image(client: &OciClient, ref: &ImageReference) -> Result<Image> {
    let manifest = client.pull_manifest(ref).await?;

    // Parallel layer download
    let layers: Vec<_> = manifest.layers()
        .map(|layer| tokio::spawn(client.pull_blob(&layer.digest)))
        .collect();

    // ... process layers
}
```

**Authentication:**
```rust
// registry/auth.rs
pub enum AuthConfig {
    None,
    Basic { username: String, password: String },
    Bearer { token: String },
    DockerConfig { path: PathBuf },
    CredentialHelper { name: String },
}
```

---

### TASK-010: Implement OverlayFS storage driver

**Effort:** 4 days | **Points:** 6 | **Priority:** P0 | **Depends On:** TASK-007

**Description:**
Implement OverlayFS layer stacking for container rootfs. Support multiple lower layers, whiteout handling, and rootless operation (kernel 5.11+).

**Acceptance Criteria:**
- [ ] Overlay mount succeeds with multiple layers
- [ ] Whiteout files correctly hide lower content
- [ ] Read-only rootfs mode supported
- [ ] Rootless overlay works (5.11+)

**Implementation Notes:**
```rust
// overlay/mod.rs
pub struct OverlayDriver {
    root: PathBuf,
}

pub struct OverlayConfig {
    lower_dirs: Vec<PathBuf>,
    upper_dir: PathBuf,
    work_dir: PathBuf,
    merged_dir: PathBuf,
}

impl OverlayDriver {
    pub fn create(&self, layers: &[Layer]) -> Result<OverlayConfig> { ... }
    pub fn mount(&self, config: &OverlayConfig) -> Result<()> {
        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            config.lower_dirs.join(":"),
            config.upper_dir.display(),
            config.work_dir.display()
        );

        mount(
            Some("overlay"),
            &config.merged_dir,
            Some("overlay"),
            MsFlags::empty(),
            Some(&options),
        )?;

        Ok(())
    }

    pub fn unmount(&self, config: &OverlayConfig) -> Result<()> { ... }
}
```

**Whiteout Handling:**
```rust
// layer/whiteout.rs
pub fn apply_whiteouts(root: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(root) {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy();

        // .wh.<filename> marks deletion
        if let Some(original) = name.strip_prefix(".wh.") {
            if original.is_empty() {
                // .wh..wh..opaq marks directory opaque
                continue;
            }

            let to_delete = entry.path().parent().unwrap().join(original);
            if to_delete.exists() {
                std::fs::remove_file(&to_delete)?;
            }
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}
```

---

### TASK-011: Implement image build from Dockerfile

**Effort:** 6 days | **Points:** 10 | **Priority:** P0 | **Depends On:** TASK-008, TASK-009, TASK-010

**Description:**
Parse Dockerfile and execute build steps. Support 95%+ directives (FROM, RUN, COPY, ADD, ENV, EXPOSE, etc.) with layer caching.

**Acceptance Criteria:**
- [ ] Parse all standard Dockerfile directives
- [ ] Build multi-stage Dockerfiles
- [ ] Layer cache invalidation correct
- [ ] Build within 15% of BuildKit performance

**Implementation Notes:**
```rust
// build/dockerfile.rs
#[derive(Debug)]
pub enum Instruction {
    From { image: String, platform: Option<String>, alias: Option<String> },
    Run { command: Vec<String> },
    Copy { src: Vec<String>, dest: String, from: Option<String>, chown: Option<String> },
    Add { src: Vec<String>, dest: String, chown: Option<String> },
    Env { key: String, value: String },
    Expose { ports: Vec<u32> },
    Workdir { path: String },
    User { user: String },
    Volume { paths: Vec<String> },
    Cmd { command: Vec<String> },
    Entrypoint { command: Vec<String> },
    Label { key: String, value: String },
    Arg { name: String, default: Option<String> },
    Healthcheck { check: HealthCheck },
    StopSignal { signal: String },
    Shell { shell: Vec<String> },
}

pub fn parse_dockerfile(content: &str) -> Result<Vec<Instruction>> { ... }
```

**Build Executor:**
```rust
// build/executor.rs
pub struct BuildExecutor {
    store: Arc<ContentStore>,
    overlay: Arc<OverlayDriver>,
    cache: BuildCache,
}

impl BuildExecutor {
    pub async fn build(&self, context: &BuildContext, dockerfile: &[Instruction]) -> Result<Image> {
        let mut current_layer = Layer::empty();

        for instruction in dockerfile {
            match instruction {
                Instruction::From { image, alias, .. } => {
                    current_layer = self.pull_base_image(image).await?;
                }
                Instruction::Run { command } => {
                    // Check cache
                    let cache_key = self.cache_key(&current_layer, command);
                    if let Some(cached) = self.cache.get(&cache_key)? {
                        current_layer = cached;
                        continue;
                    }

                    // Execute command
                    self.execute_in_container(&current_layer, command).await?;

                    // Create new layer
                    let new_layer = self.create_layer_from_changes(&current_layer)?;
                    self.cache.insert(&cache_key, &new_layer)?;
                    current_layer = new_layer;
                }
                Instruction::Copy { src, dest, .. } => {
                    self.copy_files(&mut current_layer, src, dest)?;
                }
                // ... other instructions
            }
        }

        Ok(self.finalize_image(current_layer)?)
    }
}
```

**Build Cache:**
```rust
// build/cache.rs
pub struct BuildCache {
    db: sled::Db,
}

impl BuildCache {
    pub fn get(&self, key: &str) -> Result<Option<Layer>> { ... }
    pub fn insert(&self, key: &str, layer: &Layer) -> Result<()> { ... }

    fn compute_key(&self, base_layer: &Layer, instruction: &Instruction) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&base_layer.blake3);
        hasher.update(&instruction.to_bytes());
        hex::encode(hasher.finalize().as_bytes())
    }
}
```

---

## 5. Quality Gate

### Step 1: Code Complete
- [ ] All 5 tasks marked complete
- [ ] No TODO comments in code
- [ ] All clippy warnings resolved
- [ ] Code formatted with rustfmt

### Step 2: Unit Tests
- [ ] >80% line coverage
- [ ] 100% unsafe block coverage
- [ ] Compression/decompression tests
- [ ] Hash verification tests

```bash
cargo tarpaulin --out Html --output-dir coverage/
```

### Step 3: Integration Tests
- [ ] Pull from Docker Hub
- [ ] Pull from GHCR
- [ ] Build Dockerfile
- [ ] Push to local registry

```bash
cargo test --test integration -- features="registry"
```

### Step 4: Performance Tests
- [ ] Image pull >500 MB/s
- [ ] Blake3 hash >5 GB/s
- [ ] Build within 15% of BuildKit

```bash
cargo bench --bench store
cargo bench --bench build
```

### Step 5: Security Audit
- [ ] cargo-audit clean
- [ ] Hash verification on read
- [ ] No path traversal vulnerabilities

```bash
cargo audit
```

### Step 6: Documentation
- [ ] API documentation
- [ ] Storage layout diagram
- [ ] Registry authentication guide

### Step 7: Review Sign-off
- [ ] Code review complete
- [ ] Architecture review complete

---

## 6. Dependencies

### Internal Dependencies
- ferro-exec (for running build steps)

### External Dependencies
- OCI-compliant registry (Docker Hub, GHCR, etc.)
- OverlayFS kernel support

---

## 7. Risks and Mitigations

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Registry API changes | Low | Medium | Version pinning, spec compliance |
| Large layer OOM | Medium | High | Streaming download, memory limits |
| Cache invalidation bugs | Medium | Medium | Comprehensive test cases |
| OverlayFS quota | Low | Low | Disk space monitoring |

---

## 8. Exit Criteria

Before proceeding to M2, demonstrate:

```bash
# Pull image from Docker Hub
ferrocrate pull alpine:3.19
ferrocrate images
# alpine   3.19   abc123...   5.2MB

# Run pulled image
ferrocrate run -it alpine:3.19 sh
/ # cat /etc/alpine-release
3.19.0
/ # exit

# Build image from Dockerfile
cat > Dockerfile << 'EOF'
FROM alpine:3.19
RUN apk add --no-cache curl
COPY ./app /app
CMD ["/app/start.sh"]
EOF

ferrocrate build -t myapp:v1 .
ferrocrate run myapp:v1

# Verify deduplication
ferrocrate system df
# Images: 2   Layers: 3   Shared: 1   Total: 12MB
```

---

*Milestone Owner: TBD | Last Updated: 2026-02-11*
